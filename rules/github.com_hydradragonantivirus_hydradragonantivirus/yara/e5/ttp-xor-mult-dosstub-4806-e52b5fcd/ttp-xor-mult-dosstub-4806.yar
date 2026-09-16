rule TTP_XOR_MULT_DOSStub_4806 {
  strings:
    $key_4806 = { 1c 6e [2] 68 76 [2] 2f 74 [2] 68 65 [2] 26 69 [2] 2a 63 [2] 3d 68 [2] 26 26 [2] 1b }

  condition:
    any of them
}