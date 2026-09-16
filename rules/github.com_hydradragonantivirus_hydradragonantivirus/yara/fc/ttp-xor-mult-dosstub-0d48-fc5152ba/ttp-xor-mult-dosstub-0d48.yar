rule TTP_XOR_MULT_DOSStub_0d48 {
  strings:
    $key_0d48 = { 59 20 [2] 2d 38 [2] 6a 3a [2] 2d 2b [2] 63 27 [2] 6f 2d [2] 78 26 [2] 63 68 [2] 5e }

  condition:
    any of them
}