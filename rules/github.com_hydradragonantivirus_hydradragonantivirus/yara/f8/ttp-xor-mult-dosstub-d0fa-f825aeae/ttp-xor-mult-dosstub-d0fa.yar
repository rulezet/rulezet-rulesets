rule TTP_XOR_MULT_DOSStub_d0fa {
  strings:
    $key_d0fa = { 84 92 [2] f0 8a [2] b7 88 [2] f0 99 [2] be 95 [2] b2 9f [2] a5 94 [2] be da [2] 83 }

  condition:
    any of them
}