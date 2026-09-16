rule TTP_XOR_MULT_DOSStub_8188 {
  strings:
    $key_8188 = { d5 e0 [2] a1 f8 [2] e6 fa [2] a1 eb [2] ef e7 [2] e3 ed [2] f4 e6 [2] ef a8 [2] d2 }

  condition:
    any of them
}