rule TTP_XOR_MULT_DOSStub_562a {
  strings:
    $key_562a = { 02 42 [2] 76 5a [2] 31 58 [2] 76 49 [2] 38 45 [2] 34 4f [2] 23 44 [2] 38 0a [2] 05 }

  condition:
    any of them
}