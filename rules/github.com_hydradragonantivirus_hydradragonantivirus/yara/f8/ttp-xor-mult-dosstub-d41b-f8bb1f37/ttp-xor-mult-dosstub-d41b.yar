rule TTP_XOR_MULT_DOSStub_d41b {
  strings:
    $key_d41b = { 80 73 [2] f4 6b [2] b3 69 [2] f4 78 [2] ba 74 [2] b6 7e [2] a1 75 [2] ba 3b [2] 87 }

  condition:
    any of them
}