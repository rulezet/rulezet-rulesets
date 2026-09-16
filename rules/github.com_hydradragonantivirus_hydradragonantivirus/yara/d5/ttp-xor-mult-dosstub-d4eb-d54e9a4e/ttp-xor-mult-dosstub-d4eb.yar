rule TTP_XOR_MULT_DOSStub_d4eb {
  strings:
    $key_d4eb = { 80 83 [2] f4 9b [2] b3 99 [2] f4 88 [2] ba 84 [2] b6 8e [2] a1 85 [2] ba cb [2] 87 }

  condition:
    any of them
}