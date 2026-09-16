rule TTP_XOR_MULT_DOSStub_d943 {
  strings:
    $key_d943 = { 8d 2b [2] f9 33 [2] be 31 [2] f9 20 [2] b7 2c [2] bb 26 [2] ac 2d [2] b7 63 [2] 8a }

  condition:
    any of them
}