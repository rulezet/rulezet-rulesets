rule TTP_XOR_MULT_DOSStub_44fc {
  strings:
    $key_44fc = { 10 94 [2] 64 8c [2] 23 8e [2] 64 9f [2] 2a 93 [2] 26 99 [2] 31 92 [2] 2a dc [2] 17 }

  condition:
    any of them
}