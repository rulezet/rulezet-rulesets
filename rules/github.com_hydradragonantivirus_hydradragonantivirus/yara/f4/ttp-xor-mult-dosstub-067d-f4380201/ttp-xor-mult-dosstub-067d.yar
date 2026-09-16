rule TTP_XOR_MULT_DOSStub_067d {
  strings:
    $key_067d = { 52 15 [2] 26 0d [2] 61 0f [2] 26 1e [2] 68 12 [2] 64 18 [2] 73 13 [2] 68 5d [2] 55 }

  condition:
    any of them
}