rule TTP_XOR_MULT_DOSStub_ea5e {
  strings:
    $key_ea5e = { be 36 [2] ca 2e [2] 8d 2c [2] ca 3d [2] 84 31 [2] 88 3b [2] 9f 30 [2] 84 7e [2] b9 }

  condition:
    any of them
}