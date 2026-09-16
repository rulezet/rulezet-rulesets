rule TTP_XOR_MULT_DOSStub_0d25 {
  strings:
    $key_0d25 = { 59 4d [2] 2d 55 [2] 6a 57 [2] 2d 46 [2] 63 4a [2] 6f 40 [2] 78 4b [2] 63 05 [2] 5e }

  condition:
    any of them
}