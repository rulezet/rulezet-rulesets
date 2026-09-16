rule TTP_XOR_MULT_DOSStub_4bf4 {
  strings:
    $key_4bf4 = { 1f 9c [2] 6b 84 [2] 2c 86 [2] 6b 97 [2] 25 9b [2] 29 91 [2] 3e 9a [2] 25 d4 [2] 18 }

  condition:
    any of them
}