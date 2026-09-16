rule TTP_XOR_MULT_DOSStub_0d01 {
  strings:
    $key_0d01 = { 59 69 [2] 2d 71 [2] 6a 73 [2] 2d 62 [2] 63 6e [2] 6f 64 [2] 78 6f [2] 63 21 [2] 5e }

  condition:
    any of them
}