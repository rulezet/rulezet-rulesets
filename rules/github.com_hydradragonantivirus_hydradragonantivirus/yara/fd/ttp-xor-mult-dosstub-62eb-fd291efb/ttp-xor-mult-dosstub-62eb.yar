rule TTP_XOR_MULT_DOSStub_62eb {
  strings:
    $key_62eb = { 36 83 [2] 42 9b [2] 05 99 [2] 42 88 [2] 0c 84 [2] 00 8e [2] 17 85 [2] 0c cb [2] 31 }

  condition:
    any of them
}