rule TTP_XOR_MULT_DOSStub_c22d {
  strings:
    $key_c22d = { 96 45 [2] e2 5d [2] a5 5f [2] e2 4e [2] ac 42 [2] a0 48 [2] b7 43 [2] ac 0d [2] 91 }

  condition:
    any of them
}