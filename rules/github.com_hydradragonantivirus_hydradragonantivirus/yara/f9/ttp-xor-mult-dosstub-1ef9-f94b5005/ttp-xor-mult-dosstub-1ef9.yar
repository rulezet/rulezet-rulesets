rule TTP_XOR_MULT_DOSStub_1ef9 {
  strings:
    $key_1ef9 = { 4a 91 [2] 3e 89 [2] 79 8b [2] 3e 9a [2] 70 96 [2] 7c 9c [2] 6b 97 [2] 70 d9 [2] 4d }

  condition:
    any of them
}