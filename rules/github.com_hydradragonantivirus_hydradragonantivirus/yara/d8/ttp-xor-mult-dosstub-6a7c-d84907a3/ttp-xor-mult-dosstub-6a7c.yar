rule TTP_XOR_MULT_DOSStub_6a7c {
  strings:
    $key_6a7c = { 3e 14 [2] 4a 0c [2] 0d 0e [2] 4a 1f [2] 04 13 [2] 08 19 [2] 1f 12 [2] 04 5c [2] 39 }

  condition:
    any of them
}