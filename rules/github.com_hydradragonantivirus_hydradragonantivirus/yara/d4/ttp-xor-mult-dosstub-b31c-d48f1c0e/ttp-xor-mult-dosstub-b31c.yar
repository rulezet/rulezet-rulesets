rule TTP_XOR_MULT_DOSStub_b31c {
  strings:
    $key_b31c = { e7 74 [2] 93 6c [2] d4 6e [2] 93 7f [2] dd 73 [2] d1 79 [2] c6 72 [2] dd 3c [2] e0 }

  condition:
    any of them
}