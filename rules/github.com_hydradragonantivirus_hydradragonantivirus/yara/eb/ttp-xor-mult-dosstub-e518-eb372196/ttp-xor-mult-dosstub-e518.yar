rule TTP_XOR_MULT_DOSStub_e518 {
  strings:
    $key_e518 = { b1 70 [2] c5 68 [2] 82 6a [2] c5 7b [2] 8b 77 [2] 87 7d [2] 90 76 [2] 8b 38 [2] b6 }

  condition:
    any of them
}