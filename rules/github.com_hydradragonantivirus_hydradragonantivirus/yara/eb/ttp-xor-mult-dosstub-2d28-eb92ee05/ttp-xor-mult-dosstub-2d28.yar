rule TTP_XOR_MULT_DOSStub_2d28 {
  strings:
    $key_2d28 = { 79 40 [2] 0d 58 [2] 4a 5a [2] 0d 4b [2] 43 47 [2] 4f 4d [2] 58 46 [2] 43 08 [2] 7e }

  condition:
    any of them
}