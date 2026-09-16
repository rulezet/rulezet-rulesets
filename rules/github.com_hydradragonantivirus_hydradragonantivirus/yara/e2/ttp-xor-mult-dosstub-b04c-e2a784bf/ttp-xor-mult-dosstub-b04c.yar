rule TTP_XOR_MULT_DOSStub_b04c {
  strings:
    $key_b04c = { e4 24 [2] 90 3c [2] d7 3e [2] 90 2f [2] de 23 [2] d2 29 [2] c5 22 [2] de 6c [2] e3 }

  condition:
    any of them
}