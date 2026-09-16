rule TTP_XOR_MULT_DOSStub_7d48 {
  strings:
    $key_7d48 = { 29 20 [2] 5d 38 [2] 1a 3a [2] 5d 2b [2] 13 27 [2] 1f 2d [2] 08 26 [2] 13 68 [2] 2e }

  condition:
    any of them
}