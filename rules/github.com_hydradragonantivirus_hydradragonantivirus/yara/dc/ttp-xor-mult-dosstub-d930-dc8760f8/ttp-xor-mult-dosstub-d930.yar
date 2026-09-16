rule TTP_XOR_MULT_DOSStub_d930 {
  strings:
    $key_d930 = { 8d 58 [2] f9 40 [2] be 42 [2] f9 53 [2] b7 5f [2] bb 55 [2] ac 5e [2] b7 10 [2] 8a }

  condition:
    any of them
}