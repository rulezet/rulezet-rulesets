rule TTP_XOR_MULT_DOSStub_9bdb {
  strings:
    $key_9bdb = { cf b3 [2] bb ab [2] fc a9 [2] bb b8 [2] f5 b4 [2] f9 be [2] ee b5 [2] f5 fb [2] c8 }

  condition:
    any of them
}