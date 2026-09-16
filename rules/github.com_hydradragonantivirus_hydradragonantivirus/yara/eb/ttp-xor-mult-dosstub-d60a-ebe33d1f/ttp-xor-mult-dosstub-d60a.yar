rule TTP_XOR_MULT_DOSStub_d60a {
  strings:
    $key_d60a = { 82 62 [2] f6 7a [2] b1 78 [2] f6 69 [2] b8 65 [2] b4 6f [2] a3 64 [2] b8 2a [2] 85 }

  condition:
    any of them
}