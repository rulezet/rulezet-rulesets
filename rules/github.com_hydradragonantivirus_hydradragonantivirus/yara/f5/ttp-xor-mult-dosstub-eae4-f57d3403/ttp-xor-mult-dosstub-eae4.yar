rule TTP_XOR_MULT_DOSStub_eae4 {
  strings:
    $key_eae4 = { be 8c [2] ca 94 [2] 8d 96 [2] ca 87 [2] 84 8b [2] 88 81 [2] 9f 8a [2] 84 c4 [2] b9 }

  condition:
    any of them
}