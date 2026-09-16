rule TTP_XOR_MULT_DOSStub_0d18 {
  strings:
    $key_0d18 = { 59 70 [2] 2d 68 [2] 6a 6a [2] 2d 7b [2] 63 77 [2] 6f 7d [2] 78 76 [2] 63 38 [2] 5e }

  condition:
    any of them
}