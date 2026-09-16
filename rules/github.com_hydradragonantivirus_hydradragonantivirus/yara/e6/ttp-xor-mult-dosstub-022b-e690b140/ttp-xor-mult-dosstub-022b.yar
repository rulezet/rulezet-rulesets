rule TTP_XOR_MULT_DOSStub_022b {
  strings:
    $key_022b = { 56 43 [2] 22 5b [2] 65 59 [2] 22 48 [2] 6c 44 [2] 60 4e [2] 77 45 [2] 6c 0b [2] 51 }

  condition:
    any of them
}