rule TTP_XOR_MULT_DOSStub_d0f8 {
  strings:
    $key_d0f8 = { 84 90 [2] f0 88 [2] b7 8a [2] f0 9b [2] be 97 [2] b2 9d [2] a5 96 [2] be d8 [2] 83 }

  condition:
    any of them
}