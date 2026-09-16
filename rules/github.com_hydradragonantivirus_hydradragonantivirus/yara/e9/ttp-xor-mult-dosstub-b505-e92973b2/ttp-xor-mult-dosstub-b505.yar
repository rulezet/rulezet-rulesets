rule TTP_XOR_MULT_DOSStub_b505 {
  strings:
    $key_b505 = { e1 6d [2] 95 75 [2] d2 77 [2] 95 66 [2] db 6a [2] d7 60 [2] c0 6b [2] db 25 [2] e6 }

  condition:
    any of them
}