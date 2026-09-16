rule TTP_XOR_MULT_DOSStub_d7ea {
  strings:
    $key_d7ea = { 83 82 [2] f7 9a [2] b0 98 [2] f7 89 [2] b9 85 [2] b5 8f [2] a2 84 [2] b9 ca [2] 84 }

  condition:
    any of them
}