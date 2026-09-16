rule TTP_XOR_MULT_DOSStub_db54 {
  strings:
    $key_db54 = { 8f 3c [2] fb 24 [2] bc 26 [2] fb 37 [2] b5 3b [2] b9 31 [2] ae 3a [2] b5 74 [2] 88 }

  condition:
    any of them
}