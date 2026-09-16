rule TTP_XOR_MULT_DOSStub_b27f {
  strings:
    $key_b27f = { e6 17 [2] 92 0f [2] d5 0d [2] 92 1c [2] dc 10 [2] d0 1a [2] c7 11 [2] dc 5f [2] e1 }

  condition:
    any of them
}