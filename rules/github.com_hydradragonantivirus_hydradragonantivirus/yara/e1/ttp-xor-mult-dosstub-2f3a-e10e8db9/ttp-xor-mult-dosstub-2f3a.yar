rule TTP_XOR_MULT_DOSStub_2f3a {
  strings:
    $key_2f3a = { 7b 52 [2] 0f 4a [2] 48 48 [2] 0f 59 [2] 41 55 [2] 4d 5f [2] 5a 54 [2] 41 1a [2] 7c }

  condition:
    any of them
}