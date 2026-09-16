rule TTP_XOR_MULT_DOSStub_6d72 {
  strings:
    $key_6d72 = { 39 1a [2] 4d 02 [2] 0a 00 [2] 4d 11 [2] 03 1d [2] 0f 17 [2] 18 1c [2] 03 52 [2] 3e }

  condition:
    any of them
}