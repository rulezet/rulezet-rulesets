rule TTP_XOR_MULT_DOSStub_2f78 {
  strings:
    $key_2f78 = { 7b 10 [2] 0f 08 [2] 48 0a [2] 0f 1b [2] 41 17 [2] 4d 1d [2] 5a 16 [2] 41 58 [2] 7c }

  condition:
    any of them
}