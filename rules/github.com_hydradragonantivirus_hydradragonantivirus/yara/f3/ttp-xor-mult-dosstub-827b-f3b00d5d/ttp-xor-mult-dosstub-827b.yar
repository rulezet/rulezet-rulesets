rule TTP_XOR_MULT_DOSStub_827b {
  strings:
    $key_827b = { d6 13 [2] a2 0b [2] e5 09 [2] a2 18 [2] ec 14 [2] e0 1e [2] f7 15 [2] ec 5b [2] d1 }

  condition:
    any of them
}