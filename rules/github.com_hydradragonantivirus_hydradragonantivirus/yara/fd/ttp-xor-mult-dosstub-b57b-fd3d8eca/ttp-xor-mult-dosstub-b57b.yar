rule TTP_XOR_MULT_DOSStub_b57b {
  strings:
    $key_b57b = { e1 13 [2] 95 0b [2] d2 09 [2] 95 18 [2] db 14 [2] d7 1e [2] c0 15 [2] db 5b [2] e6 }

  condition:
    any of them
}