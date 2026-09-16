rule TTP_XOR_MULT_DOSStub_b2f5 {
  strings:
    $key_b2f5 = { e6 9d [2] 92 85 [2] d5 87 [2] 92 96 [2] dc 9a [2] d0 90 [2] c7 9b [2] dc d5 [2] e1 }

  condition:
    any of them
}