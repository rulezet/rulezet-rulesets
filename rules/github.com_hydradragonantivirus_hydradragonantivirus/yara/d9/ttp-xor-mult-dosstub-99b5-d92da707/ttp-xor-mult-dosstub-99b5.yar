rule TTP_XOR_MULT_DOSStub_99b5 {
  strings:
    $key_99b5 = { cd dd [2] b9 c5 [2] fe c7 [2] b9 d6 [2] f7 da [2] fb d0 [2] ec db [2] f7 95 [2] ca }

  condition:
    any of them
}