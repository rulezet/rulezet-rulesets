rule TTP_XOR_MULT_DOSStub_68ed {
  strings:
    $key_68ed = { 3c 85 [2] 48 9d [2] 0f 9f [2] 48 8e [2] 06 82 [2] 0a 88 [2] 1d 83 [2] 06 cd [2] 3b }

  condition:
    any of them
}