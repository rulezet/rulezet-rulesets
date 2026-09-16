rule TTP_XOR_MULT_DOSStub_827a {
  strings:
    $key_827a = { d6 12 [2] a2 0a [2] e5 08 [2] a2 19 [2] ec 15 [2] e0 1f [2] f7 14 [2] ec 5a [2] d1 }

  condition:
    any of them
}