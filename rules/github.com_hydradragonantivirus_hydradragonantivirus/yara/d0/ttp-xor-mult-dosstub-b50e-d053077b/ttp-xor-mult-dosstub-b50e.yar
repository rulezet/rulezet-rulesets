rule TTP_XOR_MULT_DOSStub_b50e {
  strings:
    $key_b50e = { e1 66 [2] 95 7e [2] d2 7c [2] 95 6d [2] db 61 [2] d7 6b [2] c0 60 [2] db 2e [2] e6 }

  condition:
    any of them
}