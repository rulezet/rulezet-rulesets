rule TTP_XOR_MULT_DOSStub_ca7a {
  strings:
    $key_ca7a = { 9e 12 [2] ea 0a [2] ad 08 [2] ea 19 [2] a4 15 [2] a8 1f [2] bf 14 [2] a4 5a [2] 99 }

  condition:
    any of them
}