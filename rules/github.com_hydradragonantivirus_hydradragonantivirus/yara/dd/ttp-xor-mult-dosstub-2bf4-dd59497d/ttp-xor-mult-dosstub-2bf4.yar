rule TTP_XOR_MULT_DOSStub_2bf4 {
  strings:
    $key_2bf4 = { 7f 9c [2] 0b 84 [2] 4c 86 [2] 0b 97 [2] 45 9b [2] 49 91 [2] 5e 9a [2] 45 d4 [2] 78 }

  condition:
    any of them
}