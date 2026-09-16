rule TTP_XOR_MULT_DOSStub_38f5 {
  strings:
    $key_38f5 = { 6c 9d [2] 18 85 [2] 5f 87 [2] 18 96 [2] 56 9a [2] 5a 90 [2] 4d 9b [2] 56 d5 [2] 6b }

  condition:
    any of them
}