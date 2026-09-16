rule TTP_XOR_MULT_DOSStub_b28e {
  strings:
    $key_b28e = { e6 e6 [2] 92 fe [2] d5 fc [2] 92 ed [2] dc e1 [2] d0 eb [2] c7 e0 [2] dc ae [2] e1 }

  condition:
    any of them
}