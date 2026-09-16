rule TTP_XOR_MULT_DOSStub_5801 {
  strings:
    $key_5801 = { 0c 69 [2] 78 71 [2] 3f 73 [2] 78 62 [2] 36 6e [2] 3a 64 [2] 2d 6f [2] 36 21 [2] 0b }

  condition:
    any of them
}