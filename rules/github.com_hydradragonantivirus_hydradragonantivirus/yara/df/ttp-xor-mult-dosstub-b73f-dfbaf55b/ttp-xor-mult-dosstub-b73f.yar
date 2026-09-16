rule TTP_XOR_MULT_DOSStub_b73f {
  strings:
    $key_b73f = { e3 57 [2] 97 4f [2] d0 4d [2] 97 5c [2] d9 50 [2] d5 5a [2] c2 51 [2] d9 1f [2] e4 }

  condition:
    any of them
}