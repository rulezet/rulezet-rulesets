rule TTP_XOR_MULT_DOSStub_3d4b {
  strings:
    $key_3d4b = { 69 23 [2] 1d 3b [2] 5a 39 [2] 1d 28 [2] 53 24 [2] 5f 2e [2] 48 25 [2] 53 6b [2] 6e }

  condition:
    any of them
}