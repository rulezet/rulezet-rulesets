rule TTP_XOR_MULT_DOSStub_172d {
  strings:
    $key_172d = { 43 45 [2] 37 5d [2] 70 5f [2] 37 4e [2] 79 42 [2] 75 48 [2] 62 43 [2] 79 0d [2] 44 }

  condition:
    any of them
}