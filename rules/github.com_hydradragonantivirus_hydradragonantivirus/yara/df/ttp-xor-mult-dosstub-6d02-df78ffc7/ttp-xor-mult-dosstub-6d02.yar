rule TTP_XOR_MULT_DOSStub_6d02 {
  strings:
    $key_6d02 = { 39 6a [2] 4d 72 [2] 0a 70 [2] 4d 61 [2] 03 6d [2] 0f 67 [2] 18 6c [2] 03 22 [2] 3e }

  condition:
    any of them
}