rule TTP_XOR_MULT_DOSStub_b33b {
  strings:
    $key_b33b = { e7 53 [2] 93 4b [2] d4 49 [2] 93 58 [2] dd 54 [2] d1 5e [2] c6 55 [2] dd 1b [2] e0 }

  condition:
    any of them
}