rule TTP_XOR_MULT_DOSStub_827f {
  strings:
    $key_827f = { d6 17 [2] a2 0f [2] e5 0d [2] a2 1c [2] ec 10 [2] e0 1a [2] f7 11 [2] ec 5f [2] d1 }

  condition:
    any of them
}