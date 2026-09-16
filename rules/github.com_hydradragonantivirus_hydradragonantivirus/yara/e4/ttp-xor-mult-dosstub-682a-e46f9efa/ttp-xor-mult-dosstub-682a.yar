rule TTP_XOR_MULT_DOSStub_682a {
  strings:
    $key_682a = { 3c 42 [2] 48 5a [2] 0f 58 [2] 48 49 [2] 06 45 [2] 0a 4f [2] 1d 44 [2] 06 0a [2] 3b }

  condition:
    any of them
}