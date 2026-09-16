rule TTP_XOR_MULT_DOSStub_b72c {
  strings:
    $key_b72c = { e3 44 [2] 97 5c [2] d0 5e [2] 97 4f [2] d9 43 [2] d5 49 [2] c2 42 [2] d9 0c [2] e4 }

  condition:
    any of them
}