# # import logging
# # from datetime import datetime
# # import sys
# #
# #
# # now = datetime.now()
# #
# # file_handler = logging.FileHandler(filename = now.strftime('logs/log_%d%m%Y.log'))
# # stdout_handler = logging.StreamHandler(stream = sys.stdout)
# # handlers = [file_handler, stdout_handler]
# #
# #
# #
# # logging.basicConfig(
# #     # format = '%(asctime)s - [ %(filename)s ->  %(funcName)s() -> %(lineno)s ] - %(levelname)s: %(message)s',
# #     format = '%(asctime)s - %(levelname)s: %(message)s',
# #     # filemode = 'a',
# #     handlers = handlers
# # )
# #
# # logger = logging.getLogger(__name__)
# #
# # # Setting the threshold of logger to DEBUG
# # logger.setLevel(logging.DEBUG) # debug, warn, error, info, critical


# import logging

# # Create a logger object
# logger = logging.getLogger()

# # Set the logging level to INFO (or any other level you prefer)
# logger.setLevel(logging.INFO)

# # Create a console handler
# console_handler = logging.StreamHandler()

# # Set the logging level for the console handler
# console_handler.setLevel(logging.INFO)

# # Create a formatter for the log messages
# formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# # Set the formatter for the console handler
# console_handler.setFormatter(formatter)

# # Add the console handler to the logger
# logger.addHandler(console_handler)
