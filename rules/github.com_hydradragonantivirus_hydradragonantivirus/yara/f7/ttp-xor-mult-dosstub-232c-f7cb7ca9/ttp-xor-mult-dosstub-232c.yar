rule TTP_XOR_MULT_DOSStub_232c {
  strings:
    $key_232c = { 77 44 [2] 03 5c [2] 44 5e [2] 03 4f [2] 4d 43 [2] 41 49 [2] 56 42 [2] 4d 0c [2] 70 }

  condition:
    any of them
}