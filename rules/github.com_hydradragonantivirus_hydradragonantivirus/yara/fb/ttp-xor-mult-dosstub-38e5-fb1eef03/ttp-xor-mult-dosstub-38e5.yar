rule TTP_XOR_MULT_DOSStub_38e5 {
  strings:
    $key_38e5 = { 6c 8d [2] 18 95 [2] 5f 97 [2] 18 86 [2] 56 8a [2] 5a 80 [2] 4d 8b [2] 56 c5 [2] 6b }

  condition:
    any of them
}