# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import os
import subprocess
import tempfile
import time

from trezorlib.debuglink import TrezorClientDebugLink
from trezorlib.transport import TransportException, get_transport

BINDIR = os.path.dirname(os.path.abspath(__file__)) + "/emulators"
ENV = {"SDL_VIDEODRIVER": "dummy"}


class EmulatorWrapper:
    def __init__(self, gen, tag, storage=None):
        self.gen = gen
        self.tag = tag
        self.workdir = tempfile.TemporaryDirectory()
        if storage:
            open(self._storage_file(), "wb").write(storage)

    def __enter__(self):
        if self.tag.startswith("/"):  # full path+filename provided
            args = [self.tag]
        else:  # only gen+tag provided
            args = ["%s/trezor-emu-%s-%s" % (BINDIR, self.gen, self.tag)]
        env = ENV
        if self.gen == "core":
            args += ["-m", "main"]
            env["TREZOR_PROFILE_DIR"] = self.workdir.name
        self.process = subprocess.Popen(
            args, cwd=self.workdir.name, env=ENV, stdout=open(os.devnull, "w")
        )
        # wait until emulator is started
        while True:
            try:
                self.transport = get_transport("udp:127.0.0.1:21324")
            except TransportException:
                time.sleep(0.1)
                continue
            break
        self.client = TrezorClientDebugLink(self.transport)
        self.client.open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.client.close()
        self.process.terminate()
        try:
            self.process.wait(1)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.workdir.cleanup()

    def _storage_file(self):
        if self.gen == "legacy":
            return self.workdir.name + "/emulator.img"
        elif self.gen == "core":
            return self.workdir.name + "/trezor.flash"
        else:
            raise ValueError("Unknown gen")

    def storage(self):
        return open(self._storage_file(), "rb").read()
