rule TTP_XOR_MULT_DOSStub_8268 {
  strings:
    $key_8268 = { d6 00 [2] a2 18 [2] e5 1a [2] a2 0b [2] ec 07 [2] e0 0d [2] f7 06 [2] ec 48 [2] d1 }

  condition:
    any of them
}