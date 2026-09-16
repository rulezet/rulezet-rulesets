rule TTP_XOR_MULT_DOSStub_2839 {
  strings:
    $key_2839 = { 7c 51 [2] 08 49 [2] 4f 4b [2] 08 5a [2] 46 56 [2] 4a 5c [2] 5d 57 [2] 46 19 [2] 7b }

  condition:
    any of them
}