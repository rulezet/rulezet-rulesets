rule TTP_XOR_MULT_DOSStub_3128 {
  strings:
    $key_3128 = { 65 40 [2] 11 58 [2] 56 5a [2] 11 4b [2] 5f 47 [2] 53 4d [2] 44 46 [2] 5f 08 [2] 62 }

  condition:
    any of them
}