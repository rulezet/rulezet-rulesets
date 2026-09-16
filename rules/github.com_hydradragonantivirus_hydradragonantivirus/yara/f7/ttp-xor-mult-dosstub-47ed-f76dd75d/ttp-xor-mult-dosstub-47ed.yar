rule TTP_XOR_MULT_DOSStub_47ed {
  strings:
    $key_47ed = { 13 85 [2] 67 9d [2] 20 9f [2] 67 8e [2] 29 82 [2] 25 88 [2] 32 83 [2] 29 cd [2] 14 }

  condition:
    any of them
}