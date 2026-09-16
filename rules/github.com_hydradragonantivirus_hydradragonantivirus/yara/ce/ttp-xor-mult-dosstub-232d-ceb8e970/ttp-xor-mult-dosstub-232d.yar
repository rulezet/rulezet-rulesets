rule TTP_XOR_MULT_DOSStub_232d {
  strings:
    $key_232d = { 77 45 [2] 03 5d [2] 44 5f [2] 03 4e [2] 4d 42 [2] 41 48 [2] 56 43 [2] 4d 0d [2] 70 }

  condition:
    any of them
}