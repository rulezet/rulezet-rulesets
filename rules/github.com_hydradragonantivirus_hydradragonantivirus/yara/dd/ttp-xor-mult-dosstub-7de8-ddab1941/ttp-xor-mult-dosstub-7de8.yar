rule TTP_XOR_MULT_DOSStub_7de8 {
  strings:
    $key_7de8 = { 29 80 [2] 5d 98 [2] 1a 9a [2] 5d 8b [2] 13 87 [2] 1f 8d [2] 08 86 [2] 13 c8 [2] 2e }

  condition:
    any of them
}