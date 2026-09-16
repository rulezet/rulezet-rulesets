rule TTP_XOR_MULT_DOSStub_722a {
  strings:
    $key_722a = { 26 42 [2] 52 5a [2] 15 58 [2] 52 49 [2] 1c 45 [2] 10 4f [2] 07 44 [2] 1c 0a [2] 21 }

  condition:
    any of them
}