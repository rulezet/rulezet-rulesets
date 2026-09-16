rule TTP_XOR_MULT_DOSStub_127c {
  strings:
    $key_127c = { 46 14 [2] 32 0c [2] 75 0e [2] 32 1f [2] 7c 13 [2] 70 19 [2] 67 12 [2] 7c 5c [2] 41 }

  condition:
    any of them
}