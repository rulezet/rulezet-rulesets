rule TTP_XOR_MULT_DOSStub_84e0 {
  strings:
    $key_84e0 = { d0 88 [2] a4 90 [2] e3 92 [2] a4 83 [2] ea 8f [2] e6 85 [2] f1 8e [2] ea c0 [2] d7 }

  condition:
    any of them
}