rule TTP_XOR_MULT_DOSStub_866c {
  strings:
    $key_866c = { d2 04 [2] a6 1c [2] e1 1e [2] a6 0f [2] e8 03 [2] e4 09 [2] f3 02 [2] e8 4c [2] d5 }

  condition:
    any of them
}