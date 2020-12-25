import re
# import string
# from typing import Any, Dict, Optional

import asyncio
import serial_asyncio
# from functools import partial

import logging
LOGGER = logging.getLogger(__name__)

import zigpy.types
from zigpy.zdo.types import ZDOCmd

class CommandFailed(Exception):
    pass

class SerialProtocol(asyncio.Protocol):
    PROMPT_RE            = rb"^>\s+(.*)"
    CLI_NEWLINE_ESC_CHAR = b'\x1bE'
    CLI_COLOR_RE         = rb"(.*)\x1b\[[^m]{1,7}m(.*)"
    VT100_CURSOR_RE      = rb"(.*)\x1b\[\d+D\x1b\[J(.*)"
    LOG_RE               = rb"^.*<(info|debug|warning|error|none)> (.+?): (.+)"

    def __init__(self, tx_q, rx_q):
        self._prompt_re              = re.compile(self.PROMPT_RE)
        self._color_re               = re.compile(self.CLI_COLOR_RE)
        self._vt100_cursor_re        = re.compile(self.VT100_CURSOR_RE)
        self._log_re                 = re.compile(self.LOG_RE)
        self._tx_queue:asyncio.Queue = tx_q
        self._rx_queue:asyncio.Queue = rx_q
        self._connected              = False
        self._last_command           = None
        self._require_done           = False
        self._success_prefix         = "done"
        self._error_prefix           = "error:"
        LOGGER.info("SerialProtocol __init__")

    def connection_made(self, transport):
        LOGGER.info('Serial connection created')
        self.transport  = transport
        self.buf        = bytes()
        self._connected = True
        asyncio.ensure_future(self.send_from_queue())

    def connection_lost(self, exc):
        LOGGER.info('Serial connection closed')
        self._connected = False

    async def send_from_queue(self):
        while self._connected:
            if self._last_command == None:
                self._last_command = await self._tx_queue.get()
                self.transport.serial.write(bytes(self._last_command.encode()))
                self.transport.serial.write(b'\n')
                LOGGER.info(f'Writer sent: {self._last_command}')
                if self._last_command.lower().startswith("log"):
                    self._require_done = False
                else:
                    self._require_done = True
            else:
                await asyncio.sleep(0.1)

    def data_received(self, data):
        # Store characters until a newline is received.
        self.buf += data
        if b'\n' in self.buf:
            lines = self.buf.split(b'\n')
            self.buf = lines[-1]  # whatever was left over
            for line in lines[:-1]:
                line = self._remove_colors(line)                     # Remove color escape characters
                line = self._remove_eol_characters(line)             # Remove Additional \r and \n characters
                line = self._remove_prompt(line)                     # Prompt prefix
                # line = self._remove_non_printable_characters(line)   # Remove the non-printable characters
                log  = self._gather_logs(line)                       # Retrieve the logs
                if log is not None:
                    switcher = {
                        b'app':           self._log_app,
                        b'zigbee.report': self._log_zigbee_report,
                    }
                    func = switcher.get(log["module"]) #, lambda: "log module: {}".format(log["module"]))
                    func(log["string"])

                    continue
                line = line.decode()
                if self._last_command is not None or self._require_done:
                    if self._last_command == line:
                        # LOGGER.info(f'command echo received: {line}')
                        if not self._require_done:
                            self._last_command = None
                        continue
                    if self._require_done:
                        if line.lower().startswith(self._success_prefix):
                            LOGGER.info(f'command "{self._last_command}" was successfull')
                            self._last_command = None
                            self._require_done = False
                            continue
                        if line.lower().startswith(self._error_prefix):
                            LOGGER.info(f'command "{self._last_command}" failed ({line})')
                            cmd = self._last_command
                            self._last_command = None
                            self._require_done = False
                            # raise CommandFailed(cmd, line)
                            continue
                LOGGER.info(f'line received: {line}')

    def _log_app(self, line):
        APP_LOG_RE  = rb"(.*?) (.*)"
        _app_log_re = re.compile(APP_LOG_RE)
        found = _app_log_re.match(line)
        if found:
            if found.group(1) == b'join':
                # LOGGER.info("log <device re-/joined> %s", line)
                found   = re.compile(rb'nwk:0x([\da-fA-F]+) ieee:([\da-fA-F]+) cap:0x([\da-fA-F]+) frame:([\da-fA-F]+)').match(found.group(2))
                if len(found.group(2)) != 16:
                    LOGGER.info("<device re-/joined> IEEE address has invalid length (%s)", found.group(2))
                    return
                ieee    = bytes.fromhex(found.group(2).decode('ascii'))[::-1]
                ieee    = zigpy.types.EUI64(zigpy.types.EUI64.deserialize(ieee)[0])
                nwk     = bytes.fromhex(found.group(1).decode('ascii'))[::-1]
                nwk     = int.from_bytes(nwk, byteorder='little')
                src_ep  = 0
                dst_ep  = 0
                cluster = ZDOCmd.Device_annce
                profile = 0
                data    = found.group(4).decode('ascii')
                data    = bytes.fromhex(data)
                self._rx_queue.put_nowait({
                    "ieee"    : ieee,
                    "nwk"     : nwk,
                    "src_ep"  : src_ep,
                    "dst_ep"  : dst_ep,
                    "cluster" : cluster,
                    "profile" : profile,
                    "data"    : data
                })
            else:
                LOGGER.info("log <app> [%s] [%s]", found.group(1), found.group(2))
        else:
            LOGGER.info("log <app>: %s", line)

    def _log_zigbee_report(self, line):
        ZB_REPORT_RE  = rb".*(N|I):0x([\da-fA-F]+) SE:(\d+) DE:(\d+) P:0x([\da-fA-F]+) C:0x([\da-fA-F]+) A:0x([\da-fA-F]+) T:(\d+) V:([\d|True|False]+).*"
        _zb_report_re = re.compile(ZB_REPORT_RE)
        found = _zb_report_re.match(line)
        if found:
            if found.group(1) == b'I':
                nwk   = -1
                # ieee = zigpy.types.EUI64(zigpy.types.EUI64.deserialize(str.encode(found.group(2)))[0])
                ieee = zigpy.types.EUI64.deserialize(str.encode(found.group(2)))[0]
            elif found.group(1) == b'N':
                nwk   = int(found.group(2), 16)
                ieee  = 0
            src_ep = int(found.group(3), 10)
            dst_ep    = int(found.group(4), 10)
            profile   = int(found.group(5), 16)
            cluster   = int(found.group(6), 16)
            attr      = int(found.group(7), 16)
            type      = int(found.group(8), 10)
            if found.group(9) == b'True':
                val = 1
            elif found.group(9) == b'False':
                val = 0
            else:
                val = int(found.group(9), 10)
            LOGGER.info("0x{:04x}/0x{:016x} {}->{} Profile:0x{:04x} Cluster:0x{:04x} Attr:0x{:04x} type:{} val:{}".format(nwk, ieee, src_ep, dst_ep, profile, cluster, attr, type, val))
            # self._application.handle_rx(ieee, nwk, src_ep, dst_ep, cluster, profile, data)
        else:
            LOGGER.info("log <zigbee.report>: %s", line)

    def _remove_eol_characters(self, line):
        """ Removes every "\r" and "\n" character from input string.
            Args:
                line (str): input line
            Returns:
                str: line without "\r" and "\n" characters
        """
        return bytes("".join([chr(c) if c!=10 and c!=13 else '' for c in line]), 'ascii')

    def _remove_colors(self, line):
        """ Removes every VT100 color escape sequence from input string.
            Args:
                line (str): input line
            Returns:
                str: line without VT100 color escape sequences
        """
        colors_found = self._color_re.match(line)
        while colors_found:
            line = "".join(colors_found.groups())
            colors_found = self._color_re.match(line)

        return line

    def _remove_prompt(self, line):
        """ Removes every string prefix, equal to the prompt CLI prompt.
            Args:
                line (str): input line
            Returns:
                str: line without CLI prompt
        """
        found_prompt = self._prompt_re.match(line)
        if found_prompt:
            return found_prompt.group(1)

        return line

    def _gather_logs(self, line):
        """ Checks if the line is a log and retrieves it.
            Args:
                line (str): input line
            Returns:
                str: input line if not a log, empty string otherwise
        """
        # Remove the screen clearing
        found = self._vt100_cursor_re.match(line)
        if found:
            line = found.group(2)

            # Find the log themselves
            found = self._log_re.match(line)
            if found:
                return {"level"  : found.group(1),
                        "module" : found.group(2),
                        "string" : found.group(3)}

        return None

    def _remove_non_printable_characters(self, line):
        """ Removes all ASCII non-printable characters in a line.
            Args:
                line (str): input line
            Returns:
                str: input line without all non-printable characters
        """
        return ''.join([x if x in string.printable else '' for x in line])
