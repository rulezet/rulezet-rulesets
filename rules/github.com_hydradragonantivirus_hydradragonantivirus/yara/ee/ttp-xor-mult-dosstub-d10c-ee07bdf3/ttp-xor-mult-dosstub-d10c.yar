rule TTP_XOR_MULT_DOSStub_d10c {
  strings:
    $key_d10c = { 85 64 [2] f1 7c [2] b6 7e [2] f1 6f [2] bf 63 [2] b3 69 [2] a4 62 [2] bf 2c [2] 82 }

  condition:
    any of them
}