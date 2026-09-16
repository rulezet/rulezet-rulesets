rule TTP_XOR_MULT_DOSStub_d43b {
  strings:
    $key_d43b = { 80 53 [2] f4 4b [2] b3 49 [2] f4 58 [2] ba 54 [2] b6 5e [2] a1 55 [2] ba 1b [2] 87 }

  condition:
    any of them
}