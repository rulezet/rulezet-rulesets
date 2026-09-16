rule TTP_XOR_MULT_DOSStub_b211 {
  strings:
    $key_b211 = { e6 79 [2] 92 61 [2] d5 63 [2] 92 72 [2] dc 7e [2] d0 74 [2] c7 7f [2] dc 31 [2] e1 }

  condition:
    any of them
}