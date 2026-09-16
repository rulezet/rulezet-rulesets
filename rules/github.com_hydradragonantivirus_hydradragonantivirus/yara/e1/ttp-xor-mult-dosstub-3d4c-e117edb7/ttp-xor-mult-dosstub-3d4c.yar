rule TTP_XOR_MULT_DOSStub_3d4c {
  strings:
    $key_3d4c = { 69 24 [2] 1d 3c [2] 5a 3e [2] 1d 2f [2] 53 23 [2] 5f 29 [2] 48 22 [2] 53 6c [2] 6e }

  condition:
    any of them
}