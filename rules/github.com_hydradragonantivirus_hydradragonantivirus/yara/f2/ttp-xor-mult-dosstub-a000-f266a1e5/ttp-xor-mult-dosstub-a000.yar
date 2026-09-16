rule TTP_XOR_MULT_DOSStub_a000 {
  strings:
    $key_a000 = { f4 68 [2] 80 70 [2] c7 72 [2] 80 63 [2] ce 6f [2] c2 65 [2] d5 6e [2] ce 20 [2] f3 }

  condition:
    any of them
}