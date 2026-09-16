rule TTP_XOR_MULT_DOSStub_b3fc {
  strings:
    $key_b3fc = { e7 94 [2] 93 8c [2] d4 8e [2] 93 9f [2] dd 93 [2] d1 99 [2] c6 92 [2] dd dc [2] e0 }

  condition:
    any of them
}