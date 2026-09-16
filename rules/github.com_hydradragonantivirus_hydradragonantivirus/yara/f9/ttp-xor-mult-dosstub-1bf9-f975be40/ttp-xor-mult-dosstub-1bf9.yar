rule TTP_XOR_MULT_DOSStub_1bf9 {
  strings:
    $key_1bf9 = { 4f 91 [2] 3b 89 [2] 7c 8b [2] 3b 9a [2] 75 96 [2] 79 9c [2] 6e 97 [2] 75 d9 [2] 48 }

  condition:
    any of them
}