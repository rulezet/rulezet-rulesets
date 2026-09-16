rule TTP_XOR_MULT_DOSStub_75ed {
  strings:
    $key_75ed = { 21 85 [2] 55 9d [2] 12 9f [2] 55 8e [2] 1b 82 [2] 17 88 [2] 00 83 [2] 1b cd [2] 26 }

  condition:
    any of them
}