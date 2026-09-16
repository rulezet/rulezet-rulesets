rule TTP_XOR_MULT_DOSStub_d9f4 {
  strings:
    $key_d9f4 = { 8d 9c [2] f9 84 [2] be 86 [2] f9 97 [2] b7 9b [2] bb 91 [2] ac 9a [2] b7 d4 [2] 8a }

  condition:
    any of them
}