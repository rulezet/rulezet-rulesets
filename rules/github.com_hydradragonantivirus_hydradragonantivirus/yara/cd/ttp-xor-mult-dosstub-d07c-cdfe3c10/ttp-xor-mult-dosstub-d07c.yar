rule TTP_XOR_MULT_DOSStub_d07c {
  strings:
    $key_d07c = { 84 14 [2] f0 0c [2] b7 0e [2] f0 1f [2] be 13 [2] b2 19 [2] a5 12 [2] be 5c [2] 83 }

  condition:
    any of them
}