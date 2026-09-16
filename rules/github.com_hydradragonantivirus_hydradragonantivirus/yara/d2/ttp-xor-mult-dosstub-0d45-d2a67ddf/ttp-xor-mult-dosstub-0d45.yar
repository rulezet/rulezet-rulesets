rule TTP_XOR_MULT_DOSStub_0d45 {
  strings:
    $key_0d45 = { 59 2d [2] 2d 35 [2] 6a 37 [2] 2d 26 [2] 63 2a [2] 6f 20 [2] 78 2b [2] 63 65 [2] 5e }

  condition:
    any of them
}