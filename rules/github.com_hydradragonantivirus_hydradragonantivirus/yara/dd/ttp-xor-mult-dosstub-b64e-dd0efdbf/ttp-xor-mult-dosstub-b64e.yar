rule TTP_XOR_MULT_DOSStub_b64e {
  strings:
    $key_b64e = { e2 26 [2] 96 3e [2] d1 3c [2] 96 2d [2] d8 21 [2] d4 2b [2] c3 20 [2] d8 6e [2] e5 }

  condition:
    any of them
}