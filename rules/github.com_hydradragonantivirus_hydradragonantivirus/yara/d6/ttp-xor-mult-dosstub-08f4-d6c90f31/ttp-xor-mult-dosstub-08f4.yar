rule TTP_XOR_MULT_DOSStub_08f4 {
  strings:
    $key_08f4 = { 5c 9c [2] 28 84 [2] 6f 86 [2] 28 97 [2] 66 9b [2] 6a 91 [2] 7d 9a [2] 66 d4 [2] 5b }

  condition:
    any of them
}