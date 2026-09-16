rule TTP_XOR_MULT_DOSStub_b247 {
  strings:
    $key_b247 = { e6 2f [2] 92 37 [2] d5 35 [2] 92 24 [2] dc 28 [2] d0 22 [2] c7 29 [2] dc 67 [2] e1 }

  condition:
    any of them
}