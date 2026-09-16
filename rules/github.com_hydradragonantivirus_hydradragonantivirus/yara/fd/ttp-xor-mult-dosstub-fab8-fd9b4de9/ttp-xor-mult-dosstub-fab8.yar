rule TTP_XOR_MULT_DOSStub_fab8 {
  strings:
    $key_fab8 = { ae d0 [2] da c8 [2] 9d ca [2] da db [2] 94 d7 [2] 98 dd [2] 8f d6 [2] 94 98 [2] a9 }

  condition:
    any of them
}