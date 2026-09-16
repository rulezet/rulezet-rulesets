rule TTP_XOR_MULT_DOSStub_56f4 {
  strings:
    $key_56f4 = { 02 9c [2] 76 84 [2] 31 86 [2] 76 97 [2] 38 9b [2] 34 91 [2] 23 9a [2] 38 d4 [2] 05 }

  condition:
    any of them
}