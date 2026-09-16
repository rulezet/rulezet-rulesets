rule TTP_XOR_MULT_DOSStub_d87f {
  strings:
    $key_d87f = { 8c 17 [2] f8 0f [2] bf 0d [2] f8 1c [2] b6 10 [2] ba 1a [2] ad 11 [2] b6 5f [2] 8b }

  condition:
    any of them
}