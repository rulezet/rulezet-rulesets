rule TTP_XOR_MULT_DOSStub_017d {
  strings:
    $key_017d = { 55 15 [2] 21 0d [2] 66 0f [2] 21 1e [2] 6f 12 [2] 63 18 [2] 74 13 [2] 6f 5d [2] 52 }

  condition:
    any of them
}