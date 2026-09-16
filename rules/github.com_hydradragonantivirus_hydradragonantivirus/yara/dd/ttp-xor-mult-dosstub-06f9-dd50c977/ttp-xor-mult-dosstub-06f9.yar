rule TTP_XOR_MULT_DOSStub_06f9 {
  strings:
    $key_06f9 = { 52 91 [2] 26 89 [2] 61 8b [2] 26 9a [2] 68 96 [2] 64 9c [2] 73 97 [2] 68 d9 [2] 55 }

  condition:
    any of them
}