rule TTP_XOR_MULT_DOSStub_b201 {
  strings:
    $key_b201 = { e6 69 [2] 92 71 [2] d5 73 [2] 92 62 [2] dc 6e [2] d0 64 [2] c7 6f [2] dc 21 [2] e1 }

  condition:
    any of them
}