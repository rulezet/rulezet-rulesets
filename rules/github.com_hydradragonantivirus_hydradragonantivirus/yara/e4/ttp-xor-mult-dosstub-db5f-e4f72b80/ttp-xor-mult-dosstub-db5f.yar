rule TTP_XOR_MULT_DOSStub_db5f {
  strings:
    $key_db5f = { 8f 37 [2] fb 2f [2] bc 2d [2] fb 3c [2] b5 30 [2] b9 3a [2] ae 31 [2] b5 7f [2] 88 }

  condition:
    any of them
}