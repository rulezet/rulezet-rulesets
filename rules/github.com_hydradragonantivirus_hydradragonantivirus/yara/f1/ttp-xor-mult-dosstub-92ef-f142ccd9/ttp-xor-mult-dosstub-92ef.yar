rule TTP_XOR_MULT_DOSStub_92ef {
  strings:
    $key_92ef = { c6 87 [2] b2 9f [2] f5 9d [2] b2 8c [2] fc 80 [2] f0 8a [2] e7 81 [2] fc cf [2] c1 }

  condition:
    any of them
}