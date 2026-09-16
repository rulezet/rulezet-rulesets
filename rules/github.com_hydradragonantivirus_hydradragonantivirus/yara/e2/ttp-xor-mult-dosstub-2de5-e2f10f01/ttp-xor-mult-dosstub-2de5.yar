rule TTP_XOR_MULT_DOSStub_2de5 {
  strings:
    $key_2de5 = { 79 8d [2] 0d 95 [2] 4a 97 [2] 0d 86 [2] 43 8a [2] 4f 80 [2] 58 8b [2] 43 c5 [2] 7e }

  condition:
    any of them
}