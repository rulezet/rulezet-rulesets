rule TTP_XOR_MULT_DOSStub_822b {
  strings:
    $key_822b = { d6 43 [2] a2 5b [2] e5 59 [2] a2 48 [2] ec 44 [2] e0 4e [2] f7 45 [2] ec 0b [2] d1 }

  condition:
    any of them
}