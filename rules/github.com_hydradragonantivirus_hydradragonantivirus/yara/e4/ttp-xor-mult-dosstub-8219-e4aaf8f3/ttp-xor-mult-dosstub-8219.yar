rule TTP_XOR_MULT_DOSStub_8219 {
  strings:
    $key_8219 = { d6 71 [2] a2 69 [2] e5 6b [2] a2 7a [2] ec 76 [2] e0 7c [2] f7 77 [2] ec 39 [2] d1 }

  condition:
    any of them
}