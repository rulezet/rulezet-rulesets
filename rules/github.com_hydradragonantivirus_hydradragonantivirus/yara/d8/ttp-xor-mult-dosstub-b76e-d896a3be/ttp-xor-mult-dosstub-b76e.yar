rule TTP_XOR_MULT_DOSStub_b76e {
  strings:
    $key_b76e = { e3 06 [2] 97 1e [2] d0 1c [2] 97 0d [2] d9 01 [2] d5 0b [2] c2 00 [2] d9 4e [2] e4 }

  condition:
    any of them
}