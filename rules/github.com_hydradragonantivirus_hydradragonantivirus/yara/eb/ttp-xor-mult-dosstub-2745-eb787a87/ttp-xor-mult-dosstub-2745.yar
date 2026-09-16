rule TTP_XOR_MULT_DOSStub_2745 {
  strings:
    $key_2745 = { 73 2d [2] 07 35 [2] 40 37 [2] 07 26 [2] 49 2a [2] 45 20 [2] 52 2b [2] 49 65 [2] 74 }

  condition:
    any of them
}