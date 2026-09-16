rule TTP_XOR_MULT_DOSStub_d01e {
  strings:
    $key_d01e = { 84 76 [2] f0 6e [2] b7 6c [2] f0 7d [2] be 71 [2] b2 7b [2] a5 70 [2] be 3e [2] 83 }

  condition:
    any of them
}