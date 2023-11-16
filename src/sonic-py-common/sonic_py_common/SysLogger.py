import os
import socket
import sys
import logging
from logging.handlers import SysLogHandler


class SysLogger:
    """
    SysLogger class for Python applications using SysLogHandler
    """

    # Mapping syslog priorities to logging module levels
    LOG_LEVEL_MAP = {
        'LOG_ERR': logging.ERROR,
        'LOG_WARNING': logging.WARNING,
        'LOG_NOTICE': logging.INFO,
        'LOG_INFO': logging.INFO,
        'LOG_DEBUG': logging.DEBUG
    }

    DEFAULT_LOG_FACILITY = SysLogHandler.LOG_USER
    DEFAULT_LOG_LEVEL = SysLogHandler.LOG_INFO

    def __init__(self, log_identifier=None, log_facility=DEFAULT_LOG_FACILITY, log_level=DEFAULT_LOG_LEVEL):
        if log_identifier is None:
            log_identifier = os.path.basename(sys.argv[0])

        # Initialize SysLogger
        self.logger = logging.getLogger(log_identifier)
        self.logger.setLevel(log_level)
        handler = SysLogHandler(address="/dev/log", facility=log_facility, socktype=socket.SOCK_DGRAM)
        formatter = logging.Formatter("%(name)s: %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # Set the default minimum log priority to 'LOG_DEBUG'
        self.set_min_log_priority('LOG_DEBUG')

    def set_min_log_priority(self, priority):
        """
        Sets the minimum log priority level. All log messages
        with a priority lower than this will not be logged
        """
        self._min_log_level = self.LOG_LEVEL_MAP[priority]

    # Methods for logging messages
    def log(self, priority, msg, also_print_to_console=False):
        log_level = self.LOG_LEVEL_MAP[priority]
        if log_level >= self._min_log_level:
            self.logger.log(log_level, msg)

        if also_print_to_console:
            print(msg)

    # Convenience methods
    def log_error(self, msg, also_print_to_console=False):
        self.log('LOG_ERR', msg, also_print_to_console)

    def log_warning(self, msg, also_print_to_console=False):
        self.log('LOG_WARNING', msg, also_print_to_console)

    def log_notice(self, msg, also_print_to_console=False):
        self.log('LOG_NOTICE', msg, also_print_to_console)

    def log_info(self, msg, also_print_to_console=False):
        self.log('LOG_INFO', msg, also_print_to_console)

    def log_debug(self, msg, also_print_to_console=False):
        self.log('LOG_DEBUG', msg, also_print_to_console)
