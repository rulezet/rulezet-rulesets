rule TTP_XOR_MULT_DOSStub_f10d {
  strings:
    $key_f10d = { a5 65 [2] d1 7d [2] 96 7f [2] d1 6e [2] 9f 62 [2] 93 68 [2] 84 63 [2] 9f 2d [2] a2 }

  condition:
    any of them
}