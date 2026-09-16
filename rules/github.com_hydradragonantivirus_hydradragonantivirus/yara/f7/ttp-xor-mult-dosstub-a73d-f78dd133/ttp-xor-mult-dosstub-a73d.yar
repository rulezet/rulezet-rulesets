rule TTP_XOR_MULT_DOSStub_a73d {
  strings:
    $key_a73d = { f3 55 [2] 87 4d [2] c0 4f [2] 87 5e [2] c9 52 [2] c5 58 [2] d2 53 [2] c9 1d [2] f4 }

  condition:
    any of them
}