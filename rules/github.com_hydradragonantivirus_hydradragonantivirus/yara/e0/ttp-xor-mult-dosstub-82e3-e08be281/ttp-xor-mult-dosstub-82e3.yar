rule TTP_XOR_MULT_DOSStub_82e3 {
  strings:
    $key_82e3 = { d6 8b [2] a2 93 [2] e5 91 [2] a2 80 [2] ec 8c [2] e0 86 [2] f7 8d [2] ec c3 [2] d1 }

  condition:
    any of them
}