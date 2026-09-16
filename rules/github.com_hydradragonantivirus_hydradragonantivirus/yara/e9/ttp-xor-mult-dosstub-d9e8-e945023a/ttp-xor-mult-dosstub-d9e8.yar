rule TTP_XOR_MULT_DOSStub_d9e8 {
  strings:
    $key_d9e8 = { 8d 80 [2] f9 98 [2] be 9a [2] f9 8b [2] b7 87 [2] bb 8d [2] ac 86 [2] b7 c8 [2] 8a }

  condition:
    any of them
}