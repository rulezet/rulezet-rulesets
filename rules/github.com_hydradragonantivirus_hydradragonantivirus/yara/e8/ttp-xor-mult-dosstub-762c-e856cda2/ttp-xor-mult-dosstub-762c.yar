rule TTP_XOR_MULT_DOSStub_762c {
  strings:
    $key_762c = { 22 44 [2] 56 5c [2] 11 5e [2] 56 4f [2] 18 43 [2] 14 49 [2] 03 42 [2] 18 0c [2] 25 }

  condition:
    any of them
}