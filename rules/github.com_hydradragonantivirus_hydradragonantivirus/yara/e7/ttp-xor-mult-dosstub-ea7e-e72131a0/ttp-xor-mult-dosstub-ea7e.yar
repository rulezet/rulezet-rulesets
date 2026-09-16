rule TTP_XOR_MULT_DOSStub_ea7e {
  strings:
    $key_ea7e = { be 16 [2] ca 0e [2] 8d 0c [2] ca 1d [2] 84 11 [2] 88 1b [2] 9f 10 [2] 84 5e [2] b9 }

  condition:
    any of them
}