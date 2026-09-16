rule TTP_XOR_MULT_DOSStub_3d37 {
  strings:
    $key_3d37 = { 69 5f [2] 1d 47 [2] 5a 45 [2] 1d 54 [2] 53 58 [2] 5f 52 [2] 48 59 [2] 53 17 [2] 6e }

  condition:
    any of them
}