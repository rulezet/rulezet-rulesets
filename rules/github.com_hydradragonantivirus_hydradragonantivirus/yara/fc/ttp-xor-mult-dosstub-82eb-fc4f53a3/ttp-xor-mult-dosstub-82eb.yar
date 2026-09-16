rule TTP_XOR_MULT_DOSStub_82eb {
  strings:
    $key_82eb = { d6 83 [2] a2 9b [2] e5 99 [2] a2 88 [2] ec 84 [2] e0 8e [2] f7 85 [2] ec cb [2] d1 }

  condition:
    any of them
}