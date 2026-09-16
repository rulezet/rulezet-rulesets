rule TTP_XOR_MULT_DOSStub_db3d {
  strings:
    $key_db3d = { 8f 55 [2] fb 4d [2] bc 4f [2] fb 5e [2] b5 52 [2] b9 58 [2] ae 53 [2] b5 1d [2] 88 }

  condition:
    any of them
}