rule TTP_XOR_MULT_DOSStub_ab53 {
  strings:
    $key_ab53 = { ff 3b [2] 8b 23 [2] cc 21 [2] 8b 30 [2] c5 3c [2] c9 36 [2] de 3d [2] c5 73 [2] f8 }

  condition:
    any of them
}