rule TTP_XOR_MULT_DOSStub_d060 {
  strings:
    $key_d060 = { 84 08 [2] f0 10 [2] b7 12 [2] f0 03 [2] be 0f [2] b2 05 [2] a5 0e [2] be 40 [2] 83 }

  condition:
    any of them
}