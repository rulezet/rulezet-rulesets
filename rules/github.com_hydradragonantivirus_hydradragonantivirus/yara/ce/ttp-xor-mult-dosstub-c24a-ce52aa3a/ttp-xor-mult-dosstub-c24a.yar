rule TTP_XOR_MULT_DOSStub_c24a {
  strings:
    $key_c24a = { 96 22 [2] e2 3a [2] a5 38 [2] e2 29 [2] ac 25 [2] a0 2f [2] b7 24 [2] ac 6a [2] 91 }

  condition:
    any of them
}