rule TTP_XOR_MULT_DOSStub_f60d {
  strings:
    $key_f60d = { a2 65 [2] d6 7d [2] 91 7f [2] d6 6e [2] 98 62 [2] 94 68 [2] 83 63 [2] 98 2d [2] a5 }

  condition:
    any of them
}