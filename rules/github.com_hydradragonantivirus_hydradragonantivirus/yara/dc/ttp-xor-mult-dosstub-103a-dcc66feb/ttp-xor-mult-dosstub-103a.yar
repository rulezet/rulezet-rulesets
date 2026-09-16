rule TTP_XOR_MULT_DOSStub_103a {
  strings:
    $key_103a = { 44 52 [2] 30 4a [2] 77 48 [2] 30 59 [2] 7e 55 [2] 72 5f [2] 65 54 [2] 7e 1a [2] 43 }

  condition:
    any of them
}