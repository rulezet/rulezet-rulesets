rule TTP_XOR_MULT_DOSStub_d904 {
  strings:
    $key_d904 = { 8d 6c [2] f9 74 [2] be 76 [2] f9 67 [2] b7 6b [2] bb 61 [2] ac 6a [2] b7 24 [2] 8a }

  condition:
    any of them
}