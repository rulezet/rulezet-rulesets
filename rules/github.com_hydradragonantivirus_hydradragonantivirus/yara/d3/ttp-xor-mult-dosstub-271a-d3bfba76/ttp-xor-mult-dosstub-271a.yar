rule TTP_XOR_MULT_DOSStub_271a {
  strings:
    $key_271a = { 73 72 [2] 07 6a [2] 40 68 [2] 07 79 [2] 49 75 [2] 45 7f [2] 52 74 [2] 49 3a [2] 74 }

  condition:
    any of them
}