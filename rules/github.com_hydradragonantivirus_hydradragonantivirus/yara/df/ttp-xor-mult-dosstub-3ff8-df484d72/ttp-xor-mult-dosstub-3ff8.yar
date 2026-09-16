rule TTP_XOR_MULT_DOSStub_3ff8 {
  strings:
    $key_3ff8 = { 6b 90 [2] 1f 88 [2] 58 8a [2] 1f 9b [2] 51 97 [2] 5d 9d [2] 4a 96 [2] 51 d8 [2] 6c }

  condition:
    any of them
}