rule TTP_XOR_MULT_DOSStub_ea03 {
  strings:
    $key_ea03 = { be 6b [2] ca 73 [2] 8d 71 [2] ca 60 [2] 84 6c [2] 88 66 [2] 9f 6d [2] 84 23 [2] b9 }

  condition:
    any of them
}