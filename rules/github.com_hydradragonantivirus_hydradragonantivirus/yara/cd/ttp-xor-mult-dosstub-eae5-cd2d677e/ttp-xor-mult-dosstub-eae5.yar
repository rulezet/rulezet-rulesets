rule TTP_XOR_MULT_DOSStub_eae5 {
  strings:
    $key_eae5 = { be 8d [2] ca 95 [2] 8d 97 [2] ca 86 [2] 84 8a [2] 88 80 [2] 9f 8b [2] 84 c5 [2] b9 }

  condition:
    any of them
}