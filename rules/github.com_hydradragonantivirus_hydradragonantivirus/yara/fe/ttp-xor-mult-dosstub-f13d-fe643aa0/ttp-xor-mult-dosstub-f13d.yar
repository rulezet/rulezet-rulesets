rule TTP_XOR_MULT_DOSStub_f13d {
  strings:
    $key_f13d = { a5 55 [2] d1 4d [2] 96 4f [2] d1 5e [2] 9f 52 [2] 93 58 [2] 84 53 [2] 9f 1d [2] a2 }

  condition:
    any of them
}