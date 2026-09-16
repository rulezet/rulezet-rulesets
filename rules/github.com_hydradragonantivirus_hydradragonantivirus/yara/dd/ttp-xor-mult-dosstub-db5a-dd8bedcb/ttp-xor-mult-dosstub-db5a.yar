rule TTP_XOR_MULT_DOSStub_db5a {
  strings:
    $key_db5a = { 8f 32 [2] fb 2a [2] bc 28 [2] fb 39 [2] b5 35 [2] b9 3f [2] ae 34 [2] b5 7a [2] 88 }

  condition:
    any of them
}