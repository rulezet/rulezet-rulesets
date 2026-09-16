rule TTP_XOR_MULT_DOSStub_b25b {
  strings:
    $key_b25b = { e6 33 [2] 92 2b [2] d5 29 [2] 92 38 [2] dc 34 [2] d0 3e [2] c7 35 [2] dc 7b [2] e1 }

  condition:
    any of them
}