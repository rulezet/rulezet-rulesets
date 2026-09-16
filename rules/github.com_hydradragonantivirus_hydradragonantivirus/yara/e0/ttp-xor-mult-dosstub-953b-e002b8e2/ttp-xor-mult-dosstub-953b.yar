rule TTP_XOR_MULT_DOSStub_953b {
  strings:
    $key_953b = { c1 53 [2] b5 4b [2] f2 49 [2] b5 58 [2] fb 54 [2] f7 5e [2] e0 55 [2] fb 1b [2] c6 }

  condition:
    any of them
}