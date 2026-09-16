rule TTP_XOR_MULT_DOSStub_d901 {
  strings:
    $key_d901 = { 8d 69 [2] f9 71 [2] be 73 [2] f9 62 [2] b7 6e [2] bb 64 [2] ac 6f [2] b7 21 [2] 8a }

  condition:
    any of them
}