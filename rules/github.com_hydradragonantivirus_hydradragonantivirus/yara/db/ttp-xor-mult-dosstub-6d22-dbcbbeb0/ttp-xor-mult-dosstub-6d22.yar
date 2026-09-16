rule TTP_XOR_MULT_DOSStub_6d22 {
  strings:
    $key_6d22 = { 39 4a [2] 4d 52 [2] 0a 50 [2] 4d 41 [2] 03 4d [2] 0f 47 [2] 18 4c [2] 03 02 [2] 3e }

  condition:
    any of them
}