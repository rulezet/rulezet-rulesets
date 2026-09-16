rule TTP_XOR_MULT_DOSStub_ea7f {
  strings:
    $key_ea7f = { be 17 [2] ca 0f [2] 8d 0d [2] ca 1c [2] 84 10 [2] 88 1a [2] 9f 11 [2] 84 5f [2] b9 }

  condition:
    any of them
}