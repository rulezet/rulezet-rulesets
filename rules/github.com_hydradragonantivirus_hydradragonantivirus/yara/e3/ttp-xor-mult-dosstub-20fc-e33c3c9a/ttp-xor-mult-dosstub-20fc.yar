rule TTP_XOR_MULT_DOSStub_20fc {
  strings:
    $key_20fc = { 74 94 [2] 00 8c [2] 47 8e [2] 00 9f [2] 4e 93 [2] 42 99 [2] 55 92 [2] 4e dc [2] 73 }

  condition:
    any of them
}