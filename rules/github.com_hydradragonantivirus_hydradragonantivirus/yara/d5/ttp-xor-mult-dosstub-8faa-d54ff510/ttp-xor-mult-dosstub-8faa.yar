rule TTP_XOR_MULT_DOSStub_8faa {
  strings:
    $key_8faa = { db c2 [2] af da [2] e8 d8 [2] af c9 [2] e1 c5 [2] ed cf [2] fa c4 [2] e1 8a [2] dc }

  condition:
    any of them
}