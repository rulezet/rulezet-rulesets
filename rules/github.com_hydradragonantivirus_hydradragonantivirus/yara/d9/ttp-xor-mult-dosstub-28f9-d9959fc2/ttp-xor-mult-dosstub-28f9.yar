rule TTP_XOR_MULT_DOSStub_28f9 {
  strings:
    $key_28f9 = { 7c 91 [2] 08 89 [2] 4f 8b [2] 08 9a [2] 46 96 [2] 4a 9c [2] 5d 97 [2] 46 d9 [2] 7b }

  condition:
    any of them
}