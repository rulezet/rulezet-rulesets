rule TTP_XOR_MULT_DOSStub_93f2 {
  strings:
    $key_93f2 = { c7 9a [2] b3 82 [2] f4 80 [2] b3 91 [2] fd 9d [2] f1 97 [2] e6 9c [2] fd d2 [2] c0 }

  condition:
    any of them
}