rule TTP_XOR_MULT_DOSStub_b50b {
  strings:
    $key_b50b = { e1 63 [2] 95 7b [2] d2 79 [2] 95 68 [2] db 64 [2] d7 6e [2] c0 65 [2] db 2b [2] e6 }

  condition:
    any of them
}