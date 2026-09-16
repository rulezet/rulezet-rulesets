rule TTP_XOR_MULT_DOSStub_8cdb {
  strings:
    $key_8cdb = { d8 b3 [2] ac ab [2] eb a9 [2] ac b8 [2] e2 b4 [2] ee be [2] f9 b5 [2] e2 fb [2] df }

  condition:
    any of them
}