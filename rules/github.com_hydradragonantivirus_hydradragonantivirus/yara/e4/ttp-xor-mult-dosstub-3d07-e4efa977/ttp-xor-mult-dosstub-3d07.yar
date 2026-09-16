rule TTP_XOR_MULT_DOSStub_3d07 {
  strings:
    $key_3d07 = { 69 6f [2] 1d 77 [2] 5a 75 [2] 1d 64 [2] 53 68 [2] 5f 62 [2] 48 69 [2] 53 27 [2] 6e }

  condition:
    any of them
}