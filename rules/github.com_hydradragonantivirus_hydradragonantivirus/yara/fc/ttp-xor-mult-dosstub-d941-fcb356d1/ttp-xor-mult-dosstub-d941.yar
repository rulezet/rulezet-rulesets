rule TTP_XOR_MULT_DOSStub_d941 {
  strings:
    $key_d941 = { 8d 29 [2] f9 31 [2] be 33 [2] f9 22 [2] b7 2e [2] bb 24 [2] ac 2f [2] b7 61 [2] 8a }

  condition:
    any of them
}