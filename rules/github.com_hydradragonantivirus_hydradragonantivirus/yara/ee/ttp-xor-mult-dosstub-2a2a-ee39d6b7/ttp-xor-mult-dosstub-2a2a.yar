rule TTP_XOR_MULT_DOSStub_2a2a {
  strings:
    $key_2a2a = { 7e 42 [2] 0a 5a [2] 4d 58 [2] 0a 49 [2] 44 45 [2] 48 4f [2] 5f 44 [2] 44 0a [2] 79 }

  condition:
    any of them
}