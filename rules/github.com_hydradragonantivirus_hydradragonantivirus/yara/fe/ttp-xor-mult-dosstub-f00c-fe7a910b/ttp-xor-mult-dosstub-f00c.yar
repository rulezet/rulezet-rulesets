rule TTP_XOR_MULT_DOSStub_f00c {
  strings:
    $key_f00c = { a4 64 [2] d0 7c [2] 97 7e [2] d0 6f [2] 9e 63 [2] 92 69 [2] 85 62 [2] 9e 2c [2] a3 }

  condition:
    any of them
}