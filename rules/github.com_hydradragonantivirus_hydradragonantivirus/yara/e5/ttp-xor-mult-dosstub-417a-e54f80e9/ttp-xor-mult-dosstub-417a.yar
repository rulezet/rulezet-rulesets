rule TTP_XOR_MULT_DOSStub_417a {
  strings:
    $key_417a = { 15 12 [2] 61 0a [2] 26 08 [2] 61 19 [2] 2f 15 [2] 23 1f [2] 34 14 [2] 2f 5a [2] 12 }

  condition:
    any of them
}