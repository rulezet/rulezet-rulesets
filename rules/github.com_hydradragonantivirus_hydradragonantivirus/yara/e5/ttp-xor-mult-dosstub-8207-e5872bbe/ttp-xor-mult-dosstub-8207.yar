rule TTP_XOR_MULT_DOSStub_8207 {
  strings:
    $key_8207 = { d6 6f [2] a2 77 [2] e5 75 [2] a2 64 [2] ec 68 [2] e0 62 [2] f7 69 [2] ec 27 [2] d1 }

  condition:
    any of them
}