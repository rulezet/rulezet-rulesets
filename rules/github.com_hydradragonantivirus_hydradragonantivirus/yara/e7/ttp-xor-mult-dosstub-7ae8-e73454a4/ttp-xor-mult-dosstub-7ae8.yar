rule TTP_XOR_MULT_DOSStub_7ae8 {
  strings:
    $key_7ae8 = { 2e 80 [2] 5a 98 [2] 1d 9a [2] 5a 8b [2] 14 87 [2] 18 8d [2] 0f 86 [2] 14 c8 [2] 29 }

  condition:
    any of them
}