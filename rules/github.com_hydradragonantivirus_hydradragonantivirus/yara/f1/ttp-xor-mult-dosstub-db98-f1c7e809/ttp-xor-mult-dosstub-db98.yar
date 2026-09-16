rule TTP_XOR_MULT_DOSStub_db98 {
  strings:
    $key_db98 = { 8f f0 [2] fb e8 [2] bc ea [2] fb fb [2] b5 f7 [2] b9 fd [2] ae f6 [2] b5 b8 [2] 88 }

  condition:
    any of them
}