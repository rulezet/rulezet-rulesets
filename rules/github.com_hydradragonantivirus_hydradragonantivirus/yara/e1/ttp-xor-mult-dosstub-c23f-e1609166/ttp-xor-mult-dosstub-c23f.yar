rule TTP_XOR_MULT_DOSStub_c23f {
  strings:
    $key_c23f = { 96 57 [2] e2 4f [2] a5 4d [2] e2 5c [2] ac 50 [2] a0 5a [2] b7 51 [2] ac 1f [2] 91 }

  condition:
    any of them
}