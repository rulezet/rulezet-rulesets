rule TTP_XOR_MULT_DOSStub_9404 {
  strings:
    $key_9404 = { c0 6c [2] b4 74 [2] f3 76 [2] b4 67 [2] fa 6b [2] f6 61 [2] e1 6a [2] fa 24 [2] c7 }

  condition:
    any of them
}