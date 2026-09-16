rule TTP_XOR_MULT_DOSStub_0d26 {
  strings:
    $key_0d26 = { 59 4e [2] 2d 56 [2] 6a 54 [2] 2d 45 [2] 63 49 [2] 6f 43 [2] 78 48 [2] 63 06 [2] 5e }

  condition:
    any of them
}