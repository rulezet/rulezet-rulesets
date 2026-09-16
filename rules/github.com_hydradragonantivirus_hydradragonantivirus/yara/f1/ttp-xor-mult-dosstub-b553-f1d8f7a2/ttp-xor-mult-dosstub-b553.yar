rule TTP_XOR_MULT_DOSStub_b553 {
  strings:
    $key_b553 = { e1 3b [2] 95 23 [2] d2 21 [2] 95 30 [2] db 3c [2] d7 36 [2] c0 3d [2] db 73 [2] e6 }

  condition:
    any of them
}