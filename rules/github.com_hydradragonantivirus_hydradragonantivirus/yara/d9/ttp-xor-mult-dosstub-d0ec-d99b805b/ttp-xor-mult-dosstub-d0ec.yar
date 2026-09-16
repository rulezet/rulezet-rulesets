rule TTP_XOR_MULT_DOSStub_d0ec {
  strings:
    $key_d0ec = { 84 84 [2] f0 9c [2] b7 9e [2] f0 8f [2] be 83 [2] b2 89 [2] a5 82 [2] be cc [2] 83 }

  condition:
    any of them
}