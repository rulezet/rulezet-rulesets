rule TTP_XOR_MULT_DOSStub_ea0c {
  strings:
    $key_ea0c = { be 64 [2] ca 7c [2] 8d 7e [2] ca 6f [2] 84 63 [2] 88 69 [2] 9f 62 [2] 84 2c [2] b9 }

  condition:
    any of them
}