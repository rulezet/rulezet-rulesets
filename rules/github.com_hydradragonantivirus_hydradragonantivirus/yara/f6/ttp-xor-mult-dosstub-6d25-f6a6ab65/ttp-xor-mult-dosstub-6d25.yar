rule TTP_XOR_MULT_DOSStub_6d25 {
  strings:
    $key_6d25 = { 39 4d [2] 4d 55 [2] 0a 57 [2] 4d 46 [2] 03 4a [2] 0f 40 [2] 18 4b [2] 03 05 [2] 3e }

  condition:
    any of them
}