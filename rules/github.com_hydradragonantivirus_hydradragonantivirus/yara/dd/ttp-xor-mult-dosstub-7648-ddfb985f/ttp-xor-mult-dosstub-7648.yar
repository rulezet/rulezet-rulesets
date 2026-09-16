rule TTP_XOR_MULT_DOSStub_7648 {
  strings:
    $key_7648 = { 22 20 [2] 56 38 [2] 11 3a [2] 56 2b [2] 18 27 [2] 14 2d [2] 03 26 [2] 18 68 [2] 25 }

  condition:
    any of them
}