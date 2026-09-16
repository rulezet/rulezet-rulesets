rule TTP_XOR_MULT_DOSStub_20ed {
  strings:
    $key_20ed = { 74 85 [2] 00 9d [2] 47 9f [2] 00 8e [2] 4e 82 [2] 42 88 [2] 55 83 [2] 4e cd [2] 73 }

  condition:
    any of them
}