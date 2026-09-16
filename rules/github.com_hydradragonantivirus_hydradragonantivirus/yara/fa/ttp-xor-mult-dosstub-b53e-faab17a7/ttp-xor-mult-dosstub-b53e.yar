rule TTP_XOR_MULT_DOSStub_b53e {
  strings:
    $key_b53e = { e1 56 [2] 95 4e [2] d2 4c [2] 95 5d [2] db 51 [2] d7 5b [2] c0 50 [2] db 1e [2] e6 }

  condition:
    any of them
}