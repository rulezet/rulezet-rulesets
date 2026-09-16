rule TTP_XOR_MULT_DOSStub_d9e3 {
  strings:
    $key_d9e3 = { 8d 8b [2] f9 93 [2] be 91 [2] f9 80 [2] b7 8c [2] bb 86 [2] ac 8d [2] b7 c3 [2] 8a }

  condition:
    any of them
}