rule TTP_XOR_MULT_DOSStub_951a {
  strings:
    $key_951a = { c1 72 [2] b5 6a [2] f2 68 [2] b5 79 [2] fb 75 [2] f7 7f [2] e0 74 [2] fb 3a [2] c6 }

  condition:
    any of them
}