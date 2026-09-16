rule TTP_XOR_MULT_DOSStub_b29b {
  strings:
    $key_b29b = { e6 f3 [2] 92 eb [2] d5 e9 [2] 92 f8 [2] dc f4 [2] d0 fe [2] c7 f5 [2] dc bb [2] e1 }

  condition:
    any of them
}