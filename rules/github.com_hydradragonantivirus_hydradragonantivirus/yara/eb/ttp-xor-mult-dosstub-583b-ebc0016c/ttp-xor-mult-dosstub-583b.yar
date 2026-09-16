rule TTP_XOR_MULT_DOSStub_583b {
  strings:
    $key_583b = { 0c 53 [2] 78 4b [2] 3f 49 [2] 78 58 [2] 36 54 [2] 3a 5e [2] 2d 55 [2] 36 1b [2] 0b }

  condition:
    any of them
}