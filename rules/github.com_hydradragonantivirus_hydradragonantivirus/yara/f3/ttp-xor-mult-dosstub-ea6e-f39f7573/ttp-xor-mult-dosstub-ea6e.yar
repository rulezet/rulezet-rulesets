rule TTP_XOR_MULT_DOSStub_ea6e {
  strings:
    $key_ea6e = { be 06 [2] ca 1e [2] 8d 1c [2] ca 0d [2] 84 01 [2] 88 0b [2] 9f 00 [2] 84 4e [2] b9 }

  condition:
    any of them
}