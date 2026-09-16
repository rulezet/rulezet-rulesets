rule TTP_XOR_MULT_DOSStub_0d1b {
  strings:
    $key_0d1b = { 59 73 [2] 2d 6b [2] 6a 69 [2] 2d 78 [2] 63 74 [2] 6f 7e [2] 78 75 [2] 63 3b [2] 5e }

  condition:
    any of them
}