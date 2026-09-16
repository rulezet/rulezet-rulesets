rule TTP_XOR_MULT_DOSStub_ef56 {
  strings:
    $key_ef56 = { bb 3e [2] cf 26 [2] 88 24 [2] cf 35 [2] 81 39 [2] 8d 33 [2] 9a 38 [2] 81 76 [2] bc }

  condition:
    any of them
}