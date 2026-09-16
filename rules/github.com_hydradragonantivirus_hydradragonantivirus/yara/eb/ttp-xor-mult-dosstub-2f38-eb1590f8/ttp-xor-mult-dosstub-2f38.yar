rule TTP_XOR_MULT_DOSStub_2f38 {
  strings:
    $key_2f38 = { 7b 50 [2] 0f 48 [2] 48 4a [2] 0f 5b [2] 41 57 [2] 4d 5d [2] 5a 56 [2] 41 18 [2] 7c }

  condition:
    any of them
}