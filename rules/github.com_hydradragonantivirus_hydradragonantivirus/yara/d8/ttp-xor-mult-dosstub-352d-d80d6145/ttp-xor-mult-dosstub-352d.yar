rule TTP_XOR_MULT_DOSStub_352d {
  strings:
    $key_352d = { 61 45 [2] 15 5d [2] 52 5f [2] 15 4e [2] 5b 42 [2] 57 48 [2] 40 43 [2] 5b 0d [2] 66 }

  condition:
    any of them
}