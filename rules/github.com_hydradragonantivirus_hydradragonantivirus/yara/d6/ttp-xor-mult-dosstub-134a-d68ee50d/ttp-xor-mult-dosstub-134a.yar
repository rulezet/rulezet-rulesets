rule TTP_XOR_MULT_DOSStub_134a {
  strings:
    $key_134a = { 47 22 [2] 33 3a [2] 74 38 [2] 33 29 [2] 7d 25 [2] 71 2f [2] 66 24 [2] 7d 6a [2] 40 }

  condition:
    any of them
}