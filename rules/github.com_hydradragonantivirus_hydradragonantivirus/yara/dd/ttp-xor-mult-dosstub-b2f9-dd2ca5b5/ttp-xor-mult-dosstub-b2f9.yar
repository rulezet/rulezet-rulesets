rule TTP_XOR_MULT_DOSStub_b2f9 {
  strings:
    $key_b2f9 = { e6 91 [2] 92 89 [2] d5 8b [2] 92 9a [2] dc 96 [2] d0 9c [2] c7 97 [2] dc d9 [2] e1 }

  condition:
    any of them
}