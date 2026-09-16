rule TTP_XOR_MULT_DOSStub_d5ea {
  strings:
    $key_d5ea = { 81 82 [2] f5 9a [2] b2 98 [2] f5 89 [2] bb 85 [2] b7 8f [2] a0 84 [2] bb ca [2] 86 }

  condition:
    any of them
}