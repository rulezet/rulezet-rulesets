rule TTP_XOR_MULT_DOSStub_5d3c {
  strings:
    $key_5d3c = { 09 54 [2] 7d 4c [2] 3a 4e [2] 7d 5f [2] 33 53 [2] 3f 59 [2] 28 52 [2] 33 1c [2] 0e }

  condition:
    any of them
}