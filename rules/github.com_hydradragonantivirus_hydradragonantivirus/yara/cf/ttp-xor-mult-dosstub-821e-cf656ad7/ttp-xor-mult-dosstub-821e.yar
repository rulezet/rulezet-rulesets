rule TTP_XOR_MULT_DOSStub_821e {
  strings:
    $key_821e = { d6 76 [2] a2 6e [2] e5 6c [2] a2 7d [2] ec 71 [2] e0 7b [2] f7 70 [2] ec 3e [2] d1 }

  condition:
    any of them
}