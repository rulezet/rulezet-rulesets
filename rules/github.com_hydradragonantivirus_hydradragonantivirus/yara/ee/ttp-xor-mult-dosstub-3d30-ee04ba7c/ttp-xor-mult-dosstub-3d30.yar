rule TTP_XOR_MULT_DOSStub_3d30 {
  strings:
    $key_3d30 = { 69 58 [2] 1d 40 [2] 5a 42 [2] 1d 53 [2] 53 5f [2] 5f 55 [2] 48 5e [2] 53 10 [2] 6e }

  condition:
    any of them
}