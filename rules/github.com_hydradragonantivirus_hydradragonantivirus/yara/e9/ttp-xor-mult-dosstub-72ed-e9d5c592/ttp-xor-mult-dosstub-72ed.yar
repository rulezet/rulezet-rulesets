rule TTP_XOR_MULT_DOSStub_72ed {
  strings:
    $key_72ed = { 26 85 [2] 52 9d [2] 15 9f [2] 52 8e [2] 1c 82 [2] 10 88 [2] 07 83 [2] 1c cd [2] 21 }

  condition:
    any of them
}