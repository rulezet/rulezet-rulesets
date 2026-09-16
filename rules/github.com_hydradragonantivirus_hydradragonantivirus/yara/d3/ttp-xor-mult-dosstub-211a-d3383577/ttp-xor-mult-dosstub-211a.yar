rule TTP_XOR_MULT_DOSStub_211a {
  strings:
    $key_211a = { 75 72 [2] 01 6a [2] 46 68 [2] 01 79 [2] 4f 75 [2] 43 7f [2] 54 74 [2] 4f 3a [2] 72 }

  condition:
    any of them
}