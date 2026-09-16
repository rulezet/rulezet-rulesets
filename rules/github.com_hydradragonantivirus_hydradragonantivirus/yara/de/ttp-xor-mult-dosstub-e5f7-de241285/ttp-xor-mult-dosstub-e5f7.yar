rule TTP_XOR_MULT_DOSStub_e5f7 {
  strings:
    $key_e5f7 = { b1 9f [2] c5 87 [2] 82 85 [2] c5 94 [2] 8b 98 [2] 87 92 [2] 90 99 [2] 8b d7 [2] b6 }

  condition:
    any of them
}