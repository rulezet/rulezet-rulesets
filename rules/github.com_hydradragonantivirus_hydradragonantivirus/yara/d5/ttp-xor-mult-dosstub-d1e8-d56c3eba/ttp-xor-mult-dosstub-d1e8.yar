rule TTP_XOR_MULT_DOSStub_d1e8 {
  strings:
    $key_d1e8 = { 85 80 [2] f1 98 [2] b6 9a [2] f1 8b [2] bf 87 [2] b3 8d [2] a4 86 [2] bf c8 [2] 82 }

  condition:
    any of them
}