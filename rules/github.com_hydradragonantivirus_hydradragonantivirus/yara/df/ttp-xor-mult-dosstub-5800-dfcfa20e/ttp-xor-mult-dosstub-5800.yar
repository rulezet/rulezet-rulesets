rule TTP_XOR_MULT_DOSStub_5800 {
  strings:
    $key_5800 = { 0c 68 [2] 78 70 [2] 3f 72 [2] 78 63 [2] 36 6f [2] 3a 65 [2] 2d 6e [2] 36 20 [2] 0b }

  condition:
    any of them
}