rule TTP_XOR_MULT_DOSStub_b22f {
  strings:
    $key_b22f = { e6 47 [2] 92 5f [2] d5 5d [2] 92 4c [2] dc 40 [2] d0 4a [2] c7 41 [2] dc 0f [2] e1 }

  condition:
    any of them
}