rule TTP_XOR_MULT_DOSStub_82f4 {
  strings:
    $key_82f4 = { d6 9c [2] a2 84 [2] e5 86 [2] a2 97 [2] ec 9b [2] e0 91 [2] f7 9a [2] ec d4 [2] d1 }

  condition:
    any of them
}