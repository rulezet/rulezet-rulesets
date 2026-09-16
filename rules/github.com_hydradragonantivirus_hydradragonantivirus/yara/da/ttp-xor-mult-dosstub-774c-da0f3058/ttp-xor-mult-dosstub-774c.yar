rule TTP_XOR_MULT_DOSStub_774c {
  strings:
    $key_774c = { 23 24 [2] 57 3c [2] 10 3e [2] 57 2f [2] 19 23 [2] 15 29 [2] 02 22 [2] 19 6c [2] 24 }

  condition:
    any of them
}