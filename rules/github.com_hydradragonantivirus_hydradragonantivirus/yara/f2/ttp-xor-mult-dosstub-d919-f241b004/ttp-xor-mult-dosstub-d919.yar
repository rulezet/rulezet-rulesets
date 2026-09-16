rule TTP_XOR_MULT_DOSStub_d919 {
  strings:
    $key_d919 = { 8d 71 [2] f9 69 [2] be 6b [2] f9 7a [2] b7 76 [2] bb 7c [2] ac 77 [2] b7 39 [2] 8a }

  condition:
    any of them
}