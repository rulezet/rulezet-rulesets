rule TTP_XOR_MULT_DOSStub_d60b {
  strings:
    $key_d60b = { 82 63 [2] f6 7b [2] b1 79 [2] f6 68 [2] b8 64 [2] b4 6e [2] a3 65 [2] b8 2b [2] 85 }

  condition:
    any of them
}