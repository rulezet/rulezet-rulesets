rule TTP_XOR_MULT_DOSStub_522c {
  strings:
    $key_522c = { 06 44 [2] 72 5c [2] 35 5e [2] 72 4f [2] 3c 43 [2] 30 49 [2] 27 42 [2] 3c 0c [2] 01 }

  condition:
    any of them
}