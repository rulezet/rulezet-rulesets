rule TTP_XOR_MULT_DOSStub_db14 {
  strings:
    $key_db14 = { 8f 7c [2] fb 64 [2] bc 66 [2] fb 77 [2] b5 7b [2] b9 71 [2] ae 7a [2] b5 34 [2] 88 }

  condition:
    any of them
}