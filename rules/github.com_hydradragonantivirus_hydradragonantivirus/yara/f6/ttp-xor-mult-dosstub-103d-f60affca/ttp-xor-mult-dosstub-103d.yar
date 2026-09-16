rule TTP_XOR_MULT_DOSStub_103d {
  strings:
    $key_103d = { 44 55 [2] 30 4d [2] 77 4f [2] 30 5e [2] 7e 52 [2] 72 58 [2] 65 53 [2] 7e 1d [2] 43 }

  condition:
    any of them
}