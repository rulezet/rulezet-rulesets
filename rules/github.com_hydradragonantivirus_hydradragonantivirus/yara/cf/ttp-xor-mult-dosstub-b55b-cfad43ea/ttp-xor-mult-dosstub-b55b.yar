rule TTP_XOR_MULT_DOSStub_b55b {
  strings:
    $key_b55b = { e1 33 [2] 95 2b [2] d2 29 [2] 95 38 [2] db 34 [2] d7 3e [2] c0 35 [2] db 7b [2] e6 }

  condition:
    any of them
}