rule TTP_XOR_MULT_DOSStub_f30d {
  strings:
    $key_f30d = { a7 65 [2] d3 7d [2] 94 7f [2] d3 6e [2] 9d 62 [2] 91 68 [2] 86 63 [2] 9d 2d [2] a0 }

  condition:
    any of them
}