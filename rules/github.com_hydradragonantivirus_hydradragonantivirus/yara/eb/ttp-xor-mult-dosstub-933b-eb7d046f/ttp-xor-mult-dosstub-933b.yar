rule TTP_XOR_MULT_DOSStub_933b {
  strings:
    $key_933b = { c7 53 [2] b3 4b [2] f4 49 [2] b3 58 [2] fd 54 [2] f1 5e [2] e6 55 [2] fd 1b [2] c0 }

  condition:
    any of them
}