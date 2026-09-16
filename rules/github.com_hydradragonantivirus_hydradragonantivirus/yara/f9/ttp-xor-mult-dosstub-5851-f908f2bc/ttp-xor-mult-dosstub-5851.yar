rule TTP_XOR_MULT_DOSStub_5851 {
  strings:
    $key_5851 = { 0c 39 [2] 78 21 [2] 3f 23 [2] 78 32 [2] 36 3e [2] 3a 34 [2] 2d 3f [2] 36 71 [2] 0b }

  condition:
    any of them
}