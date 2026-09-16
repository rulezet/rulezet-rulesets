rule TTP_XOR_MULT_DOSStub_d952 {
  strings:
    $key_d952 = { 8d 3a [2] f9 22 [2] be 20 [2] f9 31 [2] b7 3d [2] bb 37 [2] ac 3c [2] b7 72 [2] 8a }

  condition:
    any of them
}