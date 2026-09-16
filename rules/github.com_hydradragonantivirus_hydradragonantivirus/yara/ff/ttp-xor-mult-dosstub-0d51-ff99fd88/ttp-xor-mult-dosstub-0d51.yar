rule TTP_XOR_MULT_DOSStub_0d51 {
  strings:
    $key_0d51 = { 59 39 [2] 2d 21 [2] 6a 23 [2] 2d 32 [2] 63 3e [2] 6f 34 [2] 78 3f [2] 63 71 [2] 5e }

  condition:
    any of them
}