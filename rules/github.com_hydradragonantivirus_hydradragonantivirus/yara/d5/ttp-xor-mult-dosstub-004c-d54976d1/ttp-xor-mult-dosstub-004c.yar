rule TTP_XOR_MULT_DOSStub_004c {
  strings:
    $key_004c = { 54 24 [2] 20 3c [2] 67 3e [2] 20 2f [2] 6e 23 [2] 62 29 [2] 75 22 [2] 6e 6c [2] 53 }

  condition:
    any of them
}