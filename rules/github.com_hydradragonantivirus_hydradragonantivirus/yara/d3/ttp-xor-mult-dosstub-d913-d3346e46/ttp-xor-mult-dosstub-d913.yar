rule TTP_XOR_MULT_DOSStub_d913 {
  strings:
    $key_d913 = { 8d 7b [2] f9 63 [2] be 61 [2] f9 70 [2] b7 7c [2] bb 76 [2] ac 7d [2] b7 33 [2] 8a }

  condition:
    any of them
}