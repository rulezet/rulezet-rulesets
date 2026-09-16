rule TTP_XOR_MULT_DOSStub_b24a {
  strings:
    $key_b24a = { e6 22 [2] 92 3a [2] d5 38 [2] 92 29 [2] dc 25 [2] d0 2f [2] c7 24 [2] dc 6a [2] e1 }

  condition:
    any of them
}