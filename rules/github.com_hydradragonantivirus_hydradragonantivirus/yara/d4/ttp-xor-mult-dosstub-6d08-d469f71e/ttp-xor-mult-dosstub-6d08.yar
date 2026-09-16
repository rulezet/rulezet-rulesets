rule TTP_XOR_MULT_DOSStub_6d08 {
  strings:
    $key_6d08 = { 39 60 [2] 4d 78 [2] 0a 7a [2] 4d 6b [2] 03 67 [2] 0f 6d [2] 18 66 [2] 03 28 [2] 3e }

  condition:
    any of them
}