rule TTP_XOR_MULT_DOSStub_313d {
  strings:
    $key_313d = { 65 55 [2] 11 4d [2] 56 4f [2] 11 5e [2] 5f 52 [2] 53 58 [2] 44 53 [2] 5f 1d [2] 62 }

  condition:
    any of them
}