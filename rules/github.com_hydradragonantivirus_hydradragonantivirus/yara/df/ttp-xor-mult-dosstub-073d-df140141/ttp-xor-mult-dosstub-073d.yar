rule TTP_XOR_MULT_DOSStub_073d {
  strings:
    $key_073d = { 53 55 [2] 27 4d [2] 60 4f [2] 27 5e [2] 69 52 [2] 65 58 [2] 72 53 [2] 69 1d [2] 54 }

  condition:
    any of them
}