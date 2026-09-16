rule TTP_XOR_MULT_DOSStub_0de7 {
  strings:
    $key_0de7 = { 59 8f [2] 2d 97 [2] 6a 95 [2] 2d 84 [2] 63 88 [2] 6f 82 [2] 78 89 [2] 63 c7 [2] 5e }

  condition:
    any of them
}