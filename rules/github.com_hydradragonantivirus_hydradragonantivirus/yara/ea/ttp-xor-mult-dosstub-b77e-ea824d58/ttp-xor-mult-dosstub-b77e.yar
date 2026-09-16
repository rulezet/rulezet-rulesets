rule TTP_XOR_MULT_DOSStub_b77e {
  strings:
    $key_b77e = { e3 16 [2] 97 0e [2] d0 0c [2] 97 1d [2] d9 11 [2] d5 1b [2] c2 10 [2] d9 5e [2] e4 }

  condition:
    any of them
}