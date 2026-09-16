rule TTP_XOR_MULT_DOSStub_823b {
  strings:
    $key_823b = { d6 53 [2] a2 4b [2] e5 49 [2] a2 58 [2] ec 54 [2] e0 5e [2] f7 55 [2] ec 1b [2] d1 }

  condition:
    any of them
}