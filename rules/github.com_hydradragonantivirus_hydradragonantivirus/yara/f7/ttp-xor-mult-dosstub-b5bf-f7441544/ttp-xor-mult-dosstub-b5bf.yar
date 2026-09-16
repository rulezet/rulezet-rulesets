rule TTP_XOR_MULT_DOSStub_b5bf {
  strings:
    $key_b5bf = { e1 d7 [2] 95 cf [2] d2 cd [2] 95 dc [2] db d0 [2] d7 da [2] c0 d1 [2] db 9f [2] e6 }

  condition:
    any of them
}