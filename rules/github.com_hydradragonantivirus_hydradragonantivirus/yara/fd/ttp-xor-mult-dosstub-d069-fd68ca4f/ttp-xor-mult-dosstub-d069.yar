rule TTP_XOR_MULT_DOSStub_d069 {
  strings:
    $key_d069 = { 84 01 [2] f0 19 [2] b7 1b [2] f0 0a [2] be 06 [2] b2 0c [2] a5 07 [2] be 49 [2] 83 }

  condition:
    any of them
}