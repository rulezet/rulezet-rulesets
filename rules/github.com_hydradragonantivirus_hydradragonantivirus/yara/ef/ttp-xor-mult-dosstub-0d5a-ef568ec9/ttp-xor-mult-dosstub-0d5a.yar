rule TTP_XOR_MULT_DOSStub_0d5a {
  strings:
    $key_0d5a = { 59 32 [2] 2d 2a [2] 6a 28 [2] 2d 39 [2] 63 35 [2] 6f 3f [2] 78 34 [2] 63 7a [2] 5e }

  condition:
    any of them
}