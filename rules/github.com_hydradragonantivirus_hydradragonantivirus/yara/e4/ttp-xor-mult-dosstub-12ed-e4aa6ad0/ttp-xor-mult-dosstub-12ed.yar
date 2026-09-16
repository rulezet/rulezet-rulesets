rule TTP_XOR_MULT_DOSStub_12ed {
  strings:
    $key_12ed = { 46 85 [2] 32 9d [2] 75 9f [2] 32 8e [2] 7c 82 [2] 70 88 [2] 67 83 [2] 7c cd [2] 41 }

  condition:
    any of them
}