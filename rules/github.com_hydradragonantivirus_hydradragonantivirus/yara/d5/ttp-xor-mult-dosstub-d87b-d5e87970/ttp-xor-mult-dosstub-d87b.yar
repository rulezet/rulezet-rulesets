rule TTP_XOR_MULT_DOSStub_d87b {
  strings:
    $key_d87b = { 8c 13 [2] f8 0b [2] bf 09 [2] f8 18 [2] b6 14 [2] ba 1e [2] ad 15 [2] b6 5b [2] 8b }

  condition:
    any of them
}