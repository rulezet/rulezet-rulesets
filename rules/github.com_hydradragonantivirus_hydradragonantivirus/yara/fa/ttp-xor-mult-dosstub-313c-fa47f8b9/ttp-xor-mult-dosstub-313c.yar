rule TTP_XOR_MULT_DOSStub_313c {
  strings:
    $key_313c = { 65 54 [2] 11 4c [2] 56 4e [2] 11 5f [2] 5f 53 [2] 53 59 [2] 44 52 [2] 5f 1c [2] 62 }

  condition:
    any of them
}