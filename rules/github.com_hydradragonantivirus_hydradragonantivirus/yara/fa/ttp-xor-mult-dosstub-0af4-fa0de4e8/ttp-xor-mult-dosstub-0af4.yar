rule TTP_XOR_MULT_DOSStub_0af4 {
  strings:
    $key_0af4 = { 5e 9c [2] 2a 84 [2] 6d 86 [2] 2a 97 [2] 64 9b [2] 68 91 [2] 7f 9a [2] 64 d4 [2] 59 }

  condition:
    any of them
}