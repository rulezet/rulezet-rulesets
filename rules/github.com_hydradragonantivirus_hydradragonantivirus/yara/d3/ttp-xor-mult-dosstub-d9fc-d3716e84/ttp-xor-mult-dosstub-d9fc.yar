rule TTP_XOR_MULT_DOSStub_d9fc {
  strings:
    $key_d9fc = { 8d 94 [2] f9 8c [2] be 8e [2] f9 9f [2] b7 93 [2] bb 99 [2] ac 92 [2] b7 dc [2] 8a }

  condition:
    any of them
}