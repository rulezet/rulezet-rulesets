rule TTP_XOR_MULT_DOSStub_05f4 {
  strings:
    $key_05f4 = { 51 9c [2] 25 84 [2] 62 86 [2] 25 97 [2] 6b 9b [2] 67 91 [2] 70 9a [2] 6b d4 [2] 56 }

  condition:
    any of them
}