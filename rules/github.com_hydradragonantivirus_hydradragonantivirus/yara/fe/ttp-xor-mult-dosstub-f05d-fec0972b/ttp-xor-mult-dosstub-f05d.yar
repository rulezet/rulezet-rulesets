rule TTP_XOR_MULT_DOSStub_f05d {
  strings:
    $key_f05d = { a4 35 [2] d0 2d [2] 97 2f [2] d0 3e [2] 9e 32 [2] 92 38 [2] 85 33 [2] 9e 7d [2] a3 }

  condition:
    any of them
}