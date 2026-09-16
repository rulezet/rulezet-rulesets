rule TTP_XOR_MULT_DOSStub_db42 {
  strings:
    $key_db42 = { 8f 2a [2] fb 32 [2] bc 30 [2] fb 21 [2] b5 2d [2] b9 27 [2] ae 2c [2] b5 62 [2] 88 }

  condition:
    any of them
}