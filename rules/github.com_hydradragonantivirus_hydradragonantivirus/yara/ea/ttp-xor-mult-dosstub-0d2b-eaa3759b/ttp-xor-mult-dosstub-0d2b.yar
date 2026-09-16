rule TTP_XOR_MULT_DOSStub_0d2b {
  strings:
    $key_0d2b = { 59 43 [2] 2d 5b [2] 6a 59 [2] 2d 48 [2] 63 44 [2] 6f 4e [2] 78 45 [2] 63 0b [2] 5e }

  condition:
    any of them
}