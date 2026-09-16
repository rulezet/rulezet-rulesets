rule TTP_XOR_MULT_DOSStub_3d28 {
  strings:
    $key_3d28 = { 69 40 [2] 1d 58 [2] 5a 5a [2] 1d 4b [2] 53 47 [2] 5f 4d [2] 48 46 [2] 53 08 [2] 6e }

  condition:
    any of them
}