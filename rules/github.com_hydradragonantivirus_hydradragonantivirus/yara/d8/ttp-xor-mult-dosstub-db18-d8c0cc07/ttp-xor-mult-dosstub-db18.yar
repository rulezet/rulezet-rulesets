rule TTP_XOR_MULT_DOSStub_db18 {
  strings:
    $key_db18 = { 8f 70 [2] fb 68 [2] bc 6a [2] fb 7b [2] b5 77 [2] b9 7d [2] ae 76 [2] b5 38 [2] 88 }

  condition:
    any of them
}