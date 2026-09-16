rule TTP_XOR_MULT_DOSStub_6d31 {
  strings:
    $key_6d31 = { 39 59 [2] 4d 41 [2] 0a 43 [2] 4d 52 [2] 03 5e [2] 0f 54 [2] 18 5f [2] 03 11 [2] 3e }

  condition:
    any of them
}