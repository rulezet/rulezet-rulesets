rule TTP_XOR_MULT_DOSStub_0d7b {
  strings:
    $key_0d7b = { 59 13 [2] 2d 0b [2] 6a 09 [2] 2d 18 [2] 63 14 [2] 6f 1e [2] 78 15 [2] 63 5b [2] 5e }

  condition:
    any of them
}