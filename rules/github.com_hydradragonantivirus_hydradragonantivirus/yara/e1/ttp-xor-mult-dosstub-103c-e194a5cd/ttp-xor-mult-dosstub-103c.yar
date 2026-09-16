rule TTP_XOR_MULT_DOSStub_103c {
  strings:
    $key_103c = { 44 54 [2] 30 4c [2] 77 4e [2] 30 5f [2] 7e 53 [2] 72 59 [2] 65 52 [2] 7e 1c [2] 43 }

  condition:
    any of them
}