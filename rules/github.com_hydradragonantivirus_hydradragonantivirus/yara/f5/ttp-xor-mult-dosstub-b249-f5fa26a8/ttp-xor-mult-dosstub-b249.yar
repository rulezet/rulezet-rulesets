rule TTP_XOR_MULT_DOSStub_b249 {
  strings:
    $key_b249 = { e6 21 [2] 92 39 [2] d5 3b [2] 92 2a [2] dc 26 [2] d0 2c [2] c7 27 [2] dc 69 [2] e1 }

  condition:
    any of them
}