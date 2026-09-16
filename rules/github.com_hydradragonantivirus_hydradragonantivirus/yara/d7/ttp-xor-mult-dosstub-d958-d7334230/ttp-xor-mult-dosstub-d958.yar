rule TTP_XOR_MULT_DOSStub_d958 {
  strings:
    $key_d958 = { 8d 30 [2] f9 28 [2] be 2a [2] f9 3b [2] b7 37 [2] bb 3d [2] ac 36 [2] b7 78 [2] 8a }

  condition:
    any of them
}