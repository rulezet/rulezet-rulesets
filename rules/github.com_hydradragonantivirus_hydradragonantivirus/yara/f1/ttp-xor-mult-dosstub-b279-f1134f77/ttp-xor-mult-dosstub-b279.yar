rule TTP_XOR_MULT_DOSStub_b279 {
  strings:
    $key_b279 = { e6 11 [2] 92 09 [2] d5 0b [2] 92 1a [2] dc 16 [2] d0 1c [2] c7 17 [2] dc 59 [2] e1 }

  condition:
    any of them
}