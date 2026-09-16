rule TTP_XOR_MULT_DOSStub_d918 {
  strings:
    $key_d918 = { 8d 70 [2] f9 68 [2] be 6a [2] f9 7b [2] b7 77 [2] bb 7d [2] ac 76 [2] b7 38 [2] 8a }

  condition:
    any of them
}