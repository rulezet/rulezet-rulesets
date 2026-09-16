rule TTP_XOR_MULT_DOSStub_b231 {
  strings:
    $key_b231 = { e6 59 [2] 92 41 [2] d5 43 [2] 92 52 [2] dc 5e [2] d0 54 [2] c7 5f [2] dc 11 [2] e1 }

  condition:
    any of them
}