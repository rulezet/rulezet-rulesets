rule TTP_XOR_MULT_DOSStub_a00d {
  strings:
    $key_a00d = { f4 65 [2] 80 7d [2] c7 7f [2] 80 6e [2] ce 62 [2] c2 68 [2] d5 63 [2] ce 2d [2] f3 }

  condition:
    any of them
}