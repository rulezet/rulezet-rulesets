rule TTP_XOR_MULT_DOSStub_dd1a {
  strings:
    $key_dd1a = { 89 72 [2] fd 6a [2] ba 68 [2] fd 79 [2] b3 75 [2] bf 7f [2] a8 74 [2] b3 3a [2] 8e }

  condition:
    any of them
}