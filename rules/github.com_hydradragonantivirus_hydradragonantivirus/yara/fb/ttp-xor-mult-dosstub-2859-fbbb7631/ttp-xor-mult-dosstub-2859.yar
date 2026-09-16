rule TTP_XOR_MULT_DOSStub_2859 {
  strings:
    $key_2859 = { 7c 31 [2] 08 29 [2] 4f 2b [2] 08 3a [2] 46 36 [2] 4a 3c [2] 5d 37 [2] 46 79 [2] 7b }

  condition:
    any of them
}