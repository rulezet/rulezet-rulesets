rule TTP_XOR_MULT_DOSStub_d928 {
  strings:
    $key_d928 = { 8d 40 [2] f9 58 [2] be 5a [2] f9 4b [2] b7 47 [2] bb 4d [2] ac 46 [2] b7 08 [2] 8a }

  condition:
    any of them
}