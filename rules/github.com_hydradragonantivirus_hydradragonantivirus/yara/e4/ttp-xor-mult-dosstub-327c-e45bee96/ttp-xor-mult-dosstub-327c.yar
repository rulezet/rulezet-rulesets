rule TTP_XOR_MULT_DOSStub_327c {
  strings:
    $key_327c = { 66 14 [2] 12 0c [2] 55 0e [2] 12 1f [2] 5c 13 [2] 50 19 [2] 47 12 [2] 5c 5c [2] 61 }

  condition:
    any of them
}