rule TTP_XOR_MULT_DOSStub_2628 {
  strings:
    $key_2628 = { 72 40 [2] 06 58 [2] 41 5a [2] 06 4b [2] 48 47 [2] 44 4d [2] 53 46 [2] 48 08 [2] 75 }

  condition:
    any of them
}