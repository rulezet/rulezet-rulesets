rule TTP_XOR_MULT_DOSStub_a07b {
  strings:
    $key_a07b = { f4 13 [2] 80 0b [2] c7 09 [2] 80 18 [2] ce 14 [2] c2 1e [2] d5 15 [2] ce 5b [2] f3 }

  condition:
    any of them
}