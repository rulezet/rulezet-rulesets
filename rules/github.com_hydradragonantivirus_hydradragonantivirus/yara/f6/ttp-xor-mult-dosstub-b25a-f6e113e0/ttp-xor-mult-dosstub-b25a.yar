rule TTP_XOR_MULT_DOSStub_b25a {
  strings:
    $key_b25a = { e6 32 [2] 92 2a [2] d5 28 [2] 92 39 [2] dc 35 [2] d0 3f [2] c7 34 [2] dc 7a [2] e1 }

  condition:
    any of them
}