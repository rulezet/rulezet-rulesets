rule TTP_XOR_MULT_DOSStub_03f4 {
  strings:
    $key_03f4 = { 57 9c [2] 23 84 [2] 64 86 [2] 23 97 [2] 6d 9b [2] 61 91 [2] 76 9a [2] 6d d4 [2] 50 }

  condition:
    any of them
}