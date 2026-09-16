rule TTP_XOR_MULT_DOSStub_2ff5 {
  strings:
    $key_2ff5 = { 7b 9d [2] 0f 85 [2] 48 87 [2] 0f 96 [2] 41 9a [2] 4d 90 [2] 5a 9b [2] 41 d5 [2] 7c }

  condition:
    any of them
}