rule TTP_XOR_MULT_DOSStub_846c {
  strings:
    $key_846c = { d0 04 [2] a4 1c [2] e3 1e [2] a4 0f [2] ea 03 [2] e6 09 [2] f1 02 [2] ea 4c [2] d7 }

  condition:
    any of them
}