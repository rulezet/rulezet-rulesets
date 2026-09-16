rule TTP_XOR_MULT_DOSStub_87ef {
  strings:
    $key_87ef = { d3 87 [2] a7 9f [2] e0 9d [2] a7 8c [2] e9 80 [2] e5 8a [2] f2 81 [2] e9 cf [2] d4 }

  condition:
    any of them
}