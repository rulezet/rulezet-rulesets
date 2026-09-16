rule TTP_XOR_MULT_DOSStub_676a {
  strings:
    $key_676a = { 33 02 [2] 47 1a [2] 00 18 [2] 47 09 [2] 09 05 [2] 05 0f [2] 12 04 [2] 09 4a [2] 34 }

  condition:
    any of them
}