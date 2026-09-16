rule TTP_XOR_MULT_DOSStub_d10b {
  strings:
    $key_d10b = { 85 63 [2] f1 7b [2] b6 79 [2] f1 68 [2] bf 64 [2] b3 6e [2] a4 65 [2] bf 2b [2] 82 }

  condition:
    any of them
}