rule TTP_XOR_MULT_DOSStub_611b {
  strings:
    $key_611b = { 35 73 [2] 41 6b [2] 06 69 [2] 41 78 [2] 0f 74 [2] 03 7e [2] 14 75 [2] 0f 3b [2] 32 }

  condition:
    any of them
}