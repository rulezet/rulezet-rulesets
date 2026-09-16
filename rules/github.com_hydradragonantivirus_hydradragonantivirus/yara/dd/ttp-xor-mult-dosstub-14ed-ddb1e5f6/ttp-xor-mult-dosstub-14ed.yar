rule TTP_XOR_MULT_DOSStub_14ed {
  strings:
    $key_14ed = { 40 85 [2] 34 9d [2] 73 9f [2] 34 8e [2] 7a 82 [2] 76 88 [2] 61 83 [2] 7a cd [2] 47 }

  condition:
    any of them
}