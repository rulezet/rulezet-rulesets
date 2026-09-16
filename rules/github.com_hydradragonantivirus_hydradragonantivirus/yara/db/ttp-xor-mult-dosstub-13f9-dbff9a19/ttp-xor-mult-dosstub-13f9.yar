rule TTP_XOR_MULT_DOSStub_13f9 {
  strings:
    $key_13f9 = { 47 91 [2] 33 89 [2] 74 8b [2] 33 9a [2] 7d 96 [2] 71 9c [2] 66 97 [2] 7d d9 [2] 40 }

  condition:
    any of them
}