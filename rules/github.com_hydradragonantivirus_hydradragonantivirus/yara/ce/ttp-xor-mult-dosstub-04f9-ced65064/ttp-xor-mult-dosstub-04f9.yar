rule TTP_XOR_MULT_DOSStub_04f9 {
  strings:
    $key_04f9 = { 50 91 [2] 24 89 [2] 63 8b [2] 24 9a [2] 6a 96 [2] 66 9c [2] 71 97 [2] 6a d9 [2] 57 }

  condition:
    any of them
}