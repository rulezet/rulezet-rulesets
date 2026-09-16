rule TTP_XOR_MULT_DOSStub_82f3 {
  strings:
    $key_82f3 = { d6 9b [2] a2 83 [2] e5 81 [2] a2 90 [2] ec 9c [2] e0 96 [2] f7 9d [2] ec d3 [2] d1 }

  condition:
    any of them
}