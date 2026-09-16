rule TTP_XOR_MULT_DOSStub_b554 {
  strings:
    $key_b554 = { e1 3c [2] 95 24 [2] d2 26 [2] 95 37 [2] db 3b [2] d7 31 [2] c0 3a [2] db 74 [2] e6 }

  condition:
    any of them
}