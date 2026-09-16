rule TTP_XOR_MULT_DOSStub_5846 {
  strings:
    $key_5846 = { 0c 2e [2] 78 36 [2] 3f 34 [2] 78 25 [2] 36 29 [2] 3a 23 [2] 2d 28 [2] 36 66 [2] 0b }

  condition:
    any of them
}