rule TTP_XOR_MULT_DOSStub_65aa {
  strings:
    $key_65aa = { 31 c2 [2] 45 da [2] 02 d8 [2] 45 c9 [2] 0b c5 [2] 07 cf [2] 10 c4 [2] 0b 8a [2] 36 }

  condition:
    any of them
}