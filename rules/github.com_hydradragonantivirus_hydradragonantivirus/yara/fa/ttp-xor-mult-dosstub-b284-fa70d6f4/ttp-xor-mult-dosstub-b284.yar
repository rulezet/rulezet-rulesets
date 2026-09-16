rule TTP_XOR_MULT_DOSStub_b284 {
  strings:
    $key_b284 = { e6 ec [2] 92 f4 [2] d5 f6 [2] 92 e7 [2] dc eb [2] d0 e1 [2] c7 ea [2] dc a4 [2] e1 }

  condition:
    any of them
}