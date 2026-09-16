rule TTP_XOR_MULT_DOSStub_d94c {
  strings:
    $key_d94c = { 8d 24 [2] f9 3c [2] be 3e [2] f9 2f [2] b7 23 [2] bb 29 [2] ac 22 [2] b7 6c [2] 8a }

  condition:
    any of them
}