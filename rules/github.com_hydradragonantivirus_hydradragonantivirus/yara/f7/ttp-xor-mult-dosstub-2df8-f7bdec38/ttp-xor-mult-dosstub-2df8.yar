rule TTP_XOR_MULT_DOSStub_2df8 {
  strings:
    $key_2df8 = { 79 90 [2] 0d 88 [2] 4a 8a [2] 0d 9b [2] 43 97 [2] 4f 9d [2] 58 96 [2] 43 d8 [2] 7e }

  condition:
    any of them
}