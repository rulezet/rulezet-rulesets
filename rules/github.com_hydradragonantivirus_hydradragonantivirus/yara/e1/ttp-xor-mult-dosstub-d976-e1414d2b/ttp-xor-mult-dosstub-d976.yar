rule TTP_XOR_MULT_DOSStub_d976 {
  strings:
    $key_d976 = { 8d 1e [2] f9 06 [2] be 04 [2] f9 15 [2] b7 19 [2] bb 13 [2] ac 18 [2] b7 56 [2] 8a }

  condition:
    any of them
}