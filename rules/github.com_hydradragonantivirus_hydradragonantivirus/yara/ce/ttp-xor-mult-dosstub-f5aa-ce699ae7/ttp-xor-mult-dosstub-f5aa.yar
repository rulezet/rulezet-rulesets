rule TTP_XOR_MULT_DOSStub_f5aa {
  strings:
    $key_f5aa = { a1 c2 [2] d5 da [2] 92 d8 [2] d5 c9 [2] 9b c5 [2] 97 cf [2] 80 c4 [2] 9b 8a [2] a6 }

  condition:
    any of them
}