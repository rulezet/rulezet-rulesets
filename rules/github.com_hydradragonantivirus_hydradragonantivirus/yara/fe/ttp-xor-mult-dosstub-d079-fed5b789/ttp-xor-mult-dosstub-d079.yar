rule TTP_XOR_MULT_DOSStub_d079 {
  strings:
    $key_d079 = { 84 11 [2] f0 09 [2] b7 0b [2] f0 1a [2] be 16 [2] b2 1c [2] a5 17 [2] be 59 [2] 83 }

  condition:
    any of them
}