rule TTP_XOR_MULT_DOSStub_64ed {
  strings:
    $key_64ed = { 30 85 [2] 44 9d [2] 03 9f [2] 44 8e [2] 0a 82 [2] 06 88 [2] 11 83 [2] 0a cd [2] 37 }

  condition:
    any of them
}