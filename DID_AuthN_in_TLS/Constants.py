# Indexes to store data in connection or context objects using
PRESENTATION_EXCHANGE_PROTOCOL_INDEX = 1
DID_METHOD_INDEX = 2
DID_INDEX = 3

# We expect the first 8 bytes of every message to describe the message length and the following byte shall be the
# message type. These are the possible message types
MESSAGE_TYPE_HTTP = 1
MESSAGE_TYPE_PRESENTATION_EXCHANGE = 2
SUBMISSION_ACK = 3
