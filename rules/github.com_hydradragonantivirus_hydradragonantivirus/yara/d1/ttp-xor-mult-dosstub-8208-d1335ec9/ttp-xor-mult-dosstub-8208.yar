rule TTP_XOR_MULT_DOSStub_8208 {
  strings:
    $key_8208 = { d6 60 [2] a2 78 [2] e5 7a [2] a2 6b [2] ec 67 [2] e0 6d [2] f7 66 [2] ec 28 [2] d1 }

  condition:
    any of them
}