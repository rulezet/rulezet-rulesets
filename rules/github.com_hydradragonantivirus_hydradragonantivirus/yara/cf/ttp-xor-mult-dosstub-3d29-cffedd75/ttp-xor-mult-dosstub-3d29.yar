rule TTP_XOR_MULT_DOSStub_3d29 {
  strings:
    $key_3d29 = { 69 41 [2] 1d 59 [2] 5a 5b [2] 1d 4a [2] 53 46 [2] 5f 4c [2] 48 47 [2] 53 09 [2] 6e }

  condition:
    any of them
}