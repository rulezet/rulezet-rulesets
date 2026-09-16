rule TTP_XOR_MULT_DOSStub_d07b {
  strings:
    $key_d07b = { 84 13 [2] f0 0b [2] b7 09 [2] f0 18 [2] be 14 [2] b2 1e [2] a5 15 [2] be 5b [2] 83 }

  condition:
    any of them
}