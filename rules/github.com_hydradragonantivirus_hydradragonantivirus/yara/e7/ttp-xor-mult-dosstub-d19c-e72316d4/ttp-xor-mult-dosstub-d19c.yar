rule TTP_XOR_MULT_DOSStub_d19c {
  strings:
    $key_d19c = { 85 f4 [2] f1 ec [2] b6 ee [2] f1 ff [2] bf f3 [2] b3 f9 [2] a4 f2 [2] bf bc [2] 82 }

  condition:
    any of them
}