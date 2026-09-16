rule TTP_XOR_MULT_DOSStub_b578 {
  strings:
    $key_b578 = { e1 10 [2] 95 08 [2] d2 0a [2] 95 1b [2] db 17 [2] d7 1d [2] c0 16 [2] db 58 [2] e6 }

  condition:
    any of them
}