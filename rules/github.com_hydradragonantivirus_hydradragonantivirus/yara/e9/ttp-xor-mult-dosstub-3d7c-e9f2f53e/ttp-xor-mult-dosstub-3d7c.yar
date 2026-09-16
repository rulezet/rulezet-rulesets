rule TTP_XOR_MULT_DOSStub_3d7c {
  strings:
    $key_3d7c = { 69 14 [2] 1d 0c [2] 5a 0e [2] 1d 1f [2] 53 13 [2] 5f 19 [2] 48 12 [2] 53 5c [2] 6e }

  condition:
    any of them
}