rule TTP_XOR_MULT_DOSStub_2ce5 {
  strings:
    $key_2ce5 = { 78 8d [2] 0c 95 [2] 4b 97 [2] 0c 86 [2] 42 8a [2] 4e 80 [2] 59 8b [2] 42 c5 [2] 7f }

  condition:
    any of them
}