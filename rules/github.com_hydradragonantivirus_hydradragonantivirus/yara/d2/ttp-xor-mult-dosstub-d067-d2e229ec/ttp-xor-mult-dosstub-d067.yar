rule TTP_XOR_MULT_DOSStub_d067 {
  strings:
    $key_d067 = { 84 0f [2] f0 17 [2] b7 15 [2] f0 04 [2] be 08 [2] b2 02 [2] a5 09 [2] be 47 [2] 83 }

  condition:
    any of them
}