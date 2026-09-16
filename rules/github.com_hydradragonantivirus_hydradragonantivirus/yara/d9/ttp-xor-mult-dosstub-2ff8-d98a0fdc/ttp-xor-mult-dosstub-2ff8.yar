rule TTP_XOR_MULT_DOSStub_2ff8 {
  strings:
    $key_2ff8 = { 7b 90 [2] 0f 88 [2] 48 8a [2] 0f 9b [2] 41 97 [2] 4d 9d [2] 5a 96 [2] 41 d8 [2] 7c }

  condition:
    any of them
}