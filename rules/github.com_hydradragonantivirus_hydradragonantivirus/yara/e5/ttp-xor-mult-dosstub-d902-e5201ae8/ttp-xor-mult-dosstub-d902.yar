rule TTP_XOR_MULT_DOSStub_d902 {
  strings:
    $key_d902 = { 8d 6a [2] f9 72 [2] be 70 [2] f9 61 [2] b7 6d [2] bb 67 [2] ac 6c [2] b7 22 [2] 8a }

  condition:
    any of them
}