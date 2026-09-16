rule TTP_XOR_MULT_DOSStub_b206 {
  strings:
    $key_b206 = { e6 6e [2] 92 76 [2] d5 74 [2] 92 65 [2] dc 69 [2] d0 63 [2] c7 68 [2] dc 26 [2] e1 }

  condition:
    any of them
}