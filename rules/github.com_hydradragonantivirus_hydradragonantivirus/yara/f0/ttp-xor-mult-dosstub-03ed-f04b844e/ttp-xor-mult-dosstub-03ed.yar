rule TTP_XOR_MULT_DOSStub_03ed {
  strings:
    $key_03ed = { 57 85 [2] 23 9d [2] 64 9f [2] 23 8e [2] 6d 82 [2] 61 88 [2] 76 83 [2] 6d cd [2] 50 }

  condition:
    any of them
}