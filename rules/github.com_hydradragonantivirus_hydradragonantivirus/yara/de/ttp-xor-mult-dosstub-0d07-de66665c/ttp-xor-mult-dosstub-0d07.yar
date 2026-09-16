rule TTP_XOR_MULT_DOSStub_0d07 {
  strings:
    $key_0d07 = { 59 6f [2] 2d 77 [2] 6a 75 [2] 2d 64 [2] 63 68 [2] 6f 62 [2] 78 69 [2] 63 27 [2] 5e }

  condition:
    any of them
}