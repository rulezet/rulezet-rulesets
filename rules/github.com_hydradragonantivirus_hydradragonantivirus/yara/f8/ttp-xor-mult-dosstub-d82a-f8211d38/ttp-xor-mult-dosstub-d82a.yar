rule TTP_XOR_MULT_DOSStub_d82a {
  strings:
    $key_d82a = { 8c 42 [2] f8 5a [2] bf 58 [2] f8 49 [2] b6 45 [2] ba 4f [2] ad 44 [2] b6 0a [2] 8b }

  condition:
    any of them
}