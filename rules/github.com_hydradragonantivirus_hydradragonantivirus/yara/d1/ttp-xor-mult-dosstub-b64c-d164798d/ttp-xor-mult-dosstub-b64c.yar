rule TTP_XOR_MULT_DOSStub_b64c {
  strings:
    $key_b64c = { e2 24 [2] 96 3c [2] d1 3e [2] 96 2f [2] d8 23 [2] d4 29 [2] c3 22 [2] d8 6c [2] e5 }

  condition:
    any of them
}