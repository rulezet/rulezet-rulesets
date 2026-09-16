rule TTP_XOR_MULT_DOSStub_b51c {
  strings:
    $key_b51c = { e1 74 [2] 95 6c [2] d2 6e [2] 95 7f [2] db 73 [2] d7 79 [2] c0 72 [2] db 3c [2] e6 }

  condition:
    any of them
}