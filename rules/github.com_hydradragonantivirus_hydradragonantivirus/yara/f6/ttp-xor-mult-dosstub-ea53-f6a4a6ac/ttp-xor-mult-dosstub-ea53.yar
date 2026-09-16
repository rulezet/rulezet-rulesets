rule TTP_XOR_MULT_DOSStub_ea53 {
  strings:
    $key_ea53 = { be 3b [2] ca 23 [2] 8d 21 [2] ca 30 [2] 84 3c [2] 88 36 [2] 9f 3d [2] 84 73 [2] b9 }

  condition:
    any of them
}