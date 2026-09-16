rule TTP_XOR_MULT_DOSStub_b6fc {
  strings:
    $key_b6fc = { e2 94 [2] 96 8c [2] d1 8e [2] 96 9f [2] d8 93 [2] d4 99 [2] c3 92 [2] d8 dc [2] e5 }

  condition:
    any of them
}