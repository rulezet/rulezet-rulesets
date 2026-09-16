rule TTP_XOR_MULT_DOSStub_d908 {
  strings:
    $key_d908 = { 8d 60 [2] f9 78 [2] be 7a [2] f9 6b [2] b7 67 [2] bb 6d [2] ac 66 [2] b7 28 [2] 8a }

  condition:
    any of them
}