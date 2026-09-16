rule TTP_XOR_MULT_DOSStub_b232 {
  strings:
    $key_b232 = { e6 5a [2] 92 42 [2] d5 40 [2] 92 51 [2] dc 5d [2] d0 57 [2] c7 5c [2] dc 12 [2] e1 }

  condition:
    any of them
}