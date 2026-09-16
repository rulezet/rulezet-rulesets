rule TTP_XOR_MULT_DOSStub_032a {
  strings:
    $key_032a = { 57 42 [2] 23 5a [2] 64 58 [2] 23 49 [2] 6d 45 [2] 61 4f [2] 76 44 [2] 6d 0a [2] 50 }

  condition:
    any of them
}