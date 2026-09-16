rule TTP_XOR_MULT_DOSStub_846b {
  strings:
    $key_846b = { d0 03 [2] a4 1b [2] e3 19 [2] a4 08 [2] ea 04 [2] e6 0e [2] f1 05 [2] ea 4b [2] d7 }

  condition:
    any of them
}