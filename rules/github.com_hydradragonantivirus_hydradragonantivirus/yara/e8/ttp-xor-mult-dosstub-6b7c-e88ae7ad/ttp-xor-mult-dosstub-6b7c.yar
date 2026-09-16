rule TTP_XOR_MULT_DOSStub_6b7c {
  strings:
    $key_6b7c = { 3f 14 [2] 4b 0c [2] 0c 0e [2] 4b 1f [2] 05 13 [2] 09 19 [2] 1e 12 [2] 05 5c [2] 38 }

  condition:
    any of them
}