rule TTP_XOR_MULT_DOSStub_db5d {
  strings:
    $key_db5d = { 8f 35 [2] fb 2d [2] bc 2f [2] fb 3e [2] b5 32 [2] b9 38 [2] ae 33 [2] b5 7d [2] 88 }

  condition:
    any of them
}