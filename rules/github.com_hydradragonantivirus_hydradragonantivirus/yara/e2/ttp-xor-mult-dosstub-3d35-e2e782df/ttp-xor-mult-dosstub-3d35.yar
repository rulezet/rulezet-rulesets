rule TTP_XOR_MULT_DOSStub_3d35 {
  strings:
    $key_3d35 = { 69 5d [2] 1d 45 [2] 5a 47 [2] 1d 56 [2] 53 5a [2] 5f 50 [2] 48 5b [2] 53 15 [2] 6e }

  condition:
    any of them
}