rule TTP_XOR_MULT_DOSStub_b53d {
  strings:
    $key_b53d = { e1 55 [2] 95 4d [2] d2 4f [2] 95 5e [2] db 52 [2] d7 58 [2] c0 53 [2] db 1d [2] e6 }

  condition:
    any of them
}