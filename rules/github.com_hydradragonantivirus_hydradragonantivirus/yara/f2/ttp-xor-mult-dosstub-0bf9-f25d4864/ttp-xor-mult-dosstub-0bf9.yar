rule TTP_XOR_MULT_DOSStub_0bf9 {
  strings:
    $key_0bf9 = { 5f 91 [2] 2b 89 [2] 6c 8b [2] 2b 9a [2] 65 96 [2] 69 9c [2] 7e 97 [2] 65 d9 [2] 58 }

  condition:
    any of them
}