rule TTP_XOR_MULT_DOSStub_82f2 {
  strings:
    $key_82f2 = { d6 9a [2] a2 82 [2] e5 80 [2] a2 91 [2] ec 9d [2] e0 97 [2] f7 9c [2] ec d2 [2] d1 }

  condition:
    any of them
}