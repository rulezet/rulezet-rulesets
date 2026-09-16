rule TTP_XOR_MULT_DOSStub_d767 {
  strings:
    $key_d767 = { 83 0f [2] f7 17 [2] b0 15 [2] f7 04 [2] b9 08 [2] b5 02 [2] a2 09 [2] b9 47 [2] 84 }

  condition:
    any of them
}