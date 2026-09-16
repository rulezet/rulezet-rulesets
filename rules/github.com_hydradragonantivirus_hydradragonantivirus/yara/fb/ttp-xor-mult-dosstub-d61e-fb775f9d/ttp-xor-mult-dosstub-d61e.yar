rule TTP_XOR_MULT_DOSStub_d61e {
  strings:
    $key_d61e = { 82 76 [2] f6 6e [2] b1 6c [2] f6 7d [2] b8 71 [2] b4 7b [2] a3 70 [2] b8 3e [2] 85 }

  condition:
    any of them
}