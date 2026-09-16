rule TTP_XOR_MULT_DOSStub_8202 {
  strings:
    $key_8202 = { d6 6a [2] a2 72 [2] e5 70 [2] a2 61 [2] ec 6d [2] e0 67 [2] f7 6c [2] ec 22 [2] d1 }

  condition:
    any of them
}