rule TTP_XOR_MULT_DOSStub_d964 {
  strings:
    $key_d964 = { 8d 0c [2] f9 14 [2] be 16 [2] f9 07 [2] b7 0b [2] bb 01 [2] ac 0a [2] b7 44 [2] 8a }

  condition:
    any of them
}