rule TTP_XOR_MULT_DOSStub_d05c {
  strings:
    $key_d05c = { 84 34 [2] f0 2c [2] b7 2e [2] f0 3f [2] be 33 [2] b2 39 [2] a5 32 [2] be 7c [2] 83 }

  condition:
    any of them
}