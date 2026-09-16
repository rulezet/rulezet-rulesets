rule TTP_XOR_MULT_DOSStub_8510 {
  strings:
    $key_8510 = { d1 78 [2] a5 60 [2] e2 62 [2] a5 73 [2] eb 7f [2] e7 75 [2] f0 7e [2] eb 30 [2] d6 }

  condition:
    any of them
}