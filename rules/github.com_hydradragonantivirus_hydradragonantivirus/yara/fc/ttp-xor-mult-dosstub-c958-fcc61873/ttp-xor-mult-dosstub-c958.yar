rule TTP_XOR_MULT_DOSStub_c958 {
  strings:
    $key_c958 = { 9d 30 [2] e9 28 [2] ae 2a [2] e9 3b [2] a7 37 [2] ab 3d [2] bc 36 [2] a7 78 [2] 9a }

  condition:
    any of them
}