rule TTP_XOR_MULT_DOSStub_d927 {
  strings:
    $key_d927 = { 8d 4f [2] f9 57 [2] be 55 [2] f9 44 [2] b7 48 [2] bb 42 [2] ac 49 [2] b7 07 [2] 8a }

  condition:
    any of them
}