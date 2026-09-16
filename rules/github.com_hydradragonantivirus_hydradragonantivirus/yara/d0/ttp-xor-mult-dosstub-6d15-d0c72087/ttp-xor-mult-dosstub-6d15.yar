rule TTP_XOR_MULT_DOSStub_6d15 {
  strings:
    $key_6d15 = { 39 7d [2] 4d 65 [2] 0a 67 [2] 4d 76 [2] 03 7a [2] 0f 70 [2] 18 7b [2] 03 35 [2] 3e }

  condition:
    any of them
}