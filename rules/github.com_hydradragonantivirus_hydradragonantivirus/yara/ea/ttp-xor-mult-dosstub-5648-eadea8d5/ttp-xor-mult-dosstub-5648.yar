rule TTP_XOR_MULT_DOSStub_5648 {
  strings:
    $key_5648 = { 02 20 [2] 76 38 [2] 31 3a [2] 76 2b [2] 38 27 [2] 34 2d [2] 23 26 [2] 38 68 [2] 05 }

  condition:
    any of them
}