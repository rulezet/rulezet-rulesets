rule TTP_XOR_MULT_DOSStub_b52b {
  strings:
    $key_b52b = { e1 43 [2] 95 5b [2] d2 59 [2] 95 48 [2] db 44 [2] d7 4e [2] c0 45 [2] db 0b [2] e6 }

  condition:
    any of them
}