rule TTP_XOR_MULT_DOSStub_2af4 {
  strings:
    $key_2af4 = { 7e 9c [2] 0a 84 [2] 4d 86 [2] 0a 97 [2] 44 9b [2] 48 91 [2] 5f 9a [2] 44 d4 [2] 79 }

  condition:
    any of them
}