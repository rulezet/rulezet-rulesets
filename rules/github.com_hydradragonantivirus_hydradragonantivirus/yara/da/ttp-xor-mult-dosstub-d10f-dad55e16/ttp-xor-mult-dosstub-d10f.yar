rule TTP_XOR_MULT_DOSStub_d10f {
  strings:
    $key_d10f = { 85 67 [2] f1 7f [2] b6 7d [2] f1 6c [2] bf 60 [2] b3 6a [2] a4 61 [2] bf 2f [2] 82 }

  condition:
    any of them
}