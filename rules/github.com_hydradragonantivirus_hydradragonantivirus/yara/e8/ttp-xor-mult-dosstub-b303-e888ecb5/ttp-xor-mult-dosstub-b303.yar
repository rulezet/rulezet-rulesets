rule TTP_XOR_MULT_DOSStub_b303 {
  strings:
    $key_b303 = { e7 6b [2] 93 73 [2] d4 71 [2] 93 60 [2] dd 6c [2] d1 66 [2] c6 6d [2] dd 23 [2] e0 }

  condition:
    any of them
}