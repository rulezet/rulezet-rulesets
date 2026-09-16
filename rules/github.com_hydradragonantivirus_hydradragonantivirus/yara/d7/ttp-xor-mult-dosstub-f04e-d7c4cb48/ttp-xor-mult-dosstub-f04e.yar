rule TTP_XOR_MULT_DOSStub_f04e {
  strings:
    $key_f04e = { a4 26 [2] d0 3e [2] 97 3c [2] d0 2d [2] 9e 21 [2] 92 2b [2] 85 20 [2] 9e 6e [2] a3 }

  condition:
    any of them
}