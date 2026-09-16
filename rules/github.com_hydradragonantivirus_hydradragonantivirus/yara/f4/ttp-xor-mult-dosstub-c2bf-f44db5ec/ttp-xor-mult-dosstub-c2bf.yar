rule TTP_XOR_MULT_DOSStub_c2bf {
  strings:
    $key_c2bf = { 96 d7 [2] e2 cf [2] a5 cd [2] e2 dc [2] ac d0 [2] a0 da [2] b7 d1 [2] ac 9f [2] 91 }

  condition:
    any of them
}