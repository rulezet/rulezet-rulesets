rule TTP_XOR_MULT_DOSStub_ea64 {
  strings:
    $key_ea64 = { be 0c [2] ca 14 [2] 8d 16 [2] ca 07 [2] 84 0b [2] 88 01 [2] 9f 0a [2] 84 44 [2] b9 }

  condition:
    any of them
}