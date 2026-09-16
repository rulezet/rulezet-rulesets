rule TTP_XOR_MULT_DOSStub_232e {
  strings:
    $key_232e = { 77 46 [2] 03 5e [2] 44 5c [2] 03 4d [2] 4d 41 [2] 41 4b [2] 56 40 [2] 4d 0e [2] 70 }

  condition:
    any of them
}