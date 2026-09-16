rule TTP_XOR_MULT_DOSStub_063d {
  strings:
    $key_063d = { 52 55 [2] 26 4d [2] 61 4f [2] 26 5e [2] 68 52 [2] 64 58 [2] 73 53 [2] 68 1d [2] 55 }

  condition:
    any of them
}