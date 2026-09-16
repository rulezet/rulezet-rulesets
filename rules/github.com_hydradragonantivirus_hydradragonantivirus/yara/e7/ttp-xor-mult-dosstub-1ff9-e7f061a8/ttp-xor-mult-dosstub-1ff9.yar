rule TTP_XOR_MULT_DOSStub_1ff9 {
  strings:
    $key_1ff9 = { 4b 91 [2] 3f 89 [2] 78 8b [2] 3f 9a [2] 71 96 [2] 7d 9c [2] 6a 97 [2] 71 d9 [2] 4c }

  condition:
    any of them
}