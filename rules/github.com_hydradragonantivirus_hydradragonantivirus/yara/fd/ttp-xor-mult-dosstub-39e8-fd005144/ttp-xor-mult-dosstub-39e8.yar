rule TTP_XOR_MULT_DOSStub_39e8 {
  strings:
    $key_39e8 = { 6d 80 [2] 19 98 [2] 5e 9a [2] 19 8b [2] 57 87 [2] 5b 8d [2] 4c 86 [2] 57 c8 [2] 6a }

  condition:
    any of them
}