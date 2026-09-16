rule TTP_XOR_MULT_DOSStub_b30c {
  strings:
    $key_b30c = { e7 64 [2] 93 7c [2] d4 7e [2] 93 6f [2] dd 63 [2] d1 69 [2] c6 62 [2] dd 2c [2] e0 }

  condition:
    any of them
}