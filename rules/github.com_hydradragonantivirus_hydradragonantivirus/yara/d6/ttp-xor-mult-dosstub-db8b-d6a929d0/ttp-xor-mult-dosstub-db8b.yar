rule TTP_XOR_MULT_DOSStub_db8b {
  strings:
    $key_db8b = { 8f e3 [2] fb fb [2] bc f9 [2] fb e8 [2] b5 e4 [2] b9 ee [2] ae e5 [2] b5 ab [2] 88 }

  condition:
    any of them
}