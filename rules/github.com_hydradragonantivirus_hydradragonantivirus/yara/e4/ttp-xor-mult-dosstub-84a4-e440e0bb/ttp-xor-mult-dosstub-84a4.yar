rule TTP_XOR_MULT_DOSStub_84a4 {
  strings:
    $key_84a4 = { d0 cc [2] a4 d4 [2] e3 d6 [2] a4 c7 [2] ea cb [2] e6 c1 [2] f1 ca [2] ea 84 [2] d7 }

  condition:
    any of them
}