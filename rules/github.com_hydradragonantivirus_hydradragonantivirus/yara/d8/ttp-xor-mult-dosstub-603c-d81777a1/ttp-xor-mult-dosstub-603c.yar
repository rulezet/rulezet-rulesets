rule TTP_XOR_MULT_DOSStub_603c {
  strings:
    $key_603c = { 34 54 [2] 40 4c [2] 07 4e [2] 40 5f [2] 0e 53 [2] 02 59 [2] 15 52 [2] 0e 1c [2] 33 }

  condition:
    any of them
}