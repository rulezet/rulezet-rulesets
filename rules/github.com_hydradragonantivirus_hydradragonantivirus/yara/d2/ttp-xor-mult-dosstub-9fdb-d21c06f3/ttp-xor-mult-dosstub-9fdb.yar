rule TTP_XOR_MULT_DOSStub_9fdb {
  strings:
    $key_9fdb = { cb b3 [2] bf ab [2] f8 a9 [2] bf b8 [2] f1 b4 [2] fd be [2] ea b5 [2] f1 fb [2] cc }

  condition:
    any of them
}