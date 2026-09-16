rule TTP_XOR_MULT_DOSStub_83bf {
  strings:
    $key_83bf = { d7 d7 [2] a3 cf [2] e4 cd [2] a3 dc [2] ed d0 [2] e1 da [2] f6 d1 [2] ed 9f [2] d0 }

  condition:
    any of them
}