rule TTP_XOR_MULT_DOSStub_3335 {
  strings:
    $key_3335 = { 67 5d [2] 13 45 [2] 54 47 [2] 13 56 [2] 5d 5a [2] 51 50 [2] 46 5b [2] 5d 15 [2] 60 }

  condition:
    any of them
}