rule TTP_XOR_MULT_DOSStub_b240 {
  strings:
    $key_b240 = { e6 28 [2] 92 30 [2] d5 32 [2] 92 23 [2] dc 2f [2] d0 25 [2] c7 2e [2] dc 60 [2] e1 }

  condition:
    any of them
}