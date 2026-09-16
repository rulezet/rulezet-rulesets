rule TTP_XOR_MULT_DOSStub_01f2 {
  strings:
    $key_01f2 = { 55 9a [2] 21 82 [2] 66 80 [2] 21 91 [2] 6f 9d [2] 63 97 [2] 74 9c [2] 6f d2 [2] 52 }

  condition:
    any of them
}