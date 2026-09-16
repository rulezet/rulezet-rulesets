rule TTP_XOR_MULT_DOSStub_d17a {
  strings:
    $key_d17a = { 85 12 [2] f1 0a [2] b6 08 [2] f1 19 [2] bf 15 [2] b3 1f [2] a4 14 [2] bf 5a [2] 82 }

  condition:
    any of them
}