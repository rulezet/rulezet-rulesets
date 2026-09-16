rule TTP_XOR_MULT_DOSStub_8267 {
  strings:
    $key_8267 = { d6 0f [2] a2 17 [2] e5 15 [2] a2 04 [2] ec 08 [2] e0 02 [2] f7 09 [2] ec 47 [2] d1 }

  condition:
    any of them
}