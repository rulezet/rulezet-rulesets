rule TTP_XOR_MULT_DOSStub_d4a3 {
  strings:
    $key_d4a3 = { 80 cb [2] f4 d3 [2] b3 d1 [2] f4 c0 [2] ba cc [2] b6 c6 [2] a1 cd [2] ba 83 [2] 87 }

  condition:
    any of them
}