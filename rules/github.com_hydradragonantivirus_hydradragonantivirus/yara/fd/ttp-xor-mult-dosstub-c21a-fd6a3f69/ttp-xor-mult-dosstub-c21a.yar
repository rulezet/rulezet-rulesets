rule TTP_XOR_MULT_DOSStub_c21a {
  strings:
    $key_c21a = { 96 72 [2] e2 6a [2] a5 68 [2] e2 79 [2] ac 75 [2] a0 7f [2] b7 74 [2] ac 3a [2] 91 }

  condition:
    any of them
}