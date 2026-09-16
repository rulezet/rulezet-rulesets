rule TTP_XOR_MULT_DOSStub_01f4 {
  strings:
    $key_01f4 = { 55 9c [2] 21 84 [2] 66 86 [2] 21 97 [2] 6f 9b [2] 63 91 [2] 74 9a [2] 6f d4 [2] 52 }

  condition:
    any of them
}