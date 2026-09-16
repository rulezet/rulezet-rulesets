rule TTP_XOR_MULT_DOSStub_6d50 {
  strings:
    $key_6d50 = { 39 38 [2] 4d 20 [2] 0a 22 [2] 4d 33 [2] 03 3f [2] 0f 35 [2] 18 3e [2] 03 70 [2] 3e }

  condition:
    any of them
}