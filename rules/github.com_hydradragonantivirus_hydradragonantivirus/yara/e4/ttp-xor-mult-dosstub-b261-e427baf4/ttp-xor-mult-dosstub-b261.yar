rule TTP_XOR_MULT_DOSStub_b261 {
  strings:
    $key_b261 = { e6 09 [2] 92 11 [2] d5 13 [2] 92 02 [2] dc 0e [2] d0 04 [2] c7 0f [2] dc 41 [2] e1 }

  condition:
    any of them
}