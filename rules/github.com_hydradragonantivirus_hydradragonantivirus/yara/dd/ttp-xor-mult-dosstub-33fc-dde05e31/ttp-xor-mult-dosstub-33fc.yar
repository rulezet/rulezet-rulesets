rule TTP_XOR_MULT_DOSStub_33fc {
  strings:
    $key_33fc = { 67 94 [2] 13 8c [2] 54 8e [2] 13 9f [2] 5d 93 [2] 51 99 [2] 46 92 [2] 5d dc [2] 60 }

  condition:
    any of them
}