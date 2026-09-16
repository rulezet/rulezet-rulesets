rule TTP_XOR_MULT_DOSStub_174c {
  strings:
    $key_174c = { 43 24 [2] 37 3c [2] 70 3e [2] 37 2f [2] 79 23 [2] 75 29 [2] 62 22 [2] 79 6c [2] 44 }

  condition:
    any of them
}