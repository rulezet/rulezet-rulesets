rule TTP_XOR_MULT_DOSStub_8230 {
  strings:
    $key_8230 = { d6 58 [2] a2 40 [2] e5 42 [2] a2 53 [2] ec 5f [2] e0 55 [2] f7 5e [2] ec 10 [2] d1 }

  condition:
    any of them
}