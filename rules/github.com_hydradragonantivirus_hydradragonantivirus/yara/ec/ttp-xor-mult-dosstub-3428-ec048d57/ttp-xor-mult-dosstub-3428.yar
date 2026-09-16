rule TTP_XOR_MULT_DOSStub_3428 {
  strings:
    $key_3428 = { 60 40 [2] 14 58 [2] 53 5a [2] 14 4b [2] 5a 47 [2] 56 4d [2] 41 46 [2] 5a 08 [2] 67 }

  condition:
    any of them
}