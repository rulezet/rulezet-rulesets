rule TTP_XOR_MULT_DOSStub_b21a {
  strings:
    $key_b21a = { e6 72 [2] 92 6a [2] d5 68 [2] 92 79 [2] dc 75 [2] d0 7f [2] c7 74 [2] dc 3a [2] e1 }

  condition:
    any of them
}