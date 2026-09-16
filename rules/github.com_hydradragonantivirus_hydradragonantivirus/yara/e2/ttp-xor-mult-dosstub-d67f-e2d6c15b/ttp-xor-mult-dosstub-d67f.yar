rule TTP_XOR_MULT_DOSStub_d67f {
  strings:
    $key_d67f = { 82 17 [2] f6 0f [2] b1 0d [2] f6 1c [2] b8 10 [2] b4 1a [2] a3 11 [2] b8 5f [2] 85 }

  condition:
    any of them
}