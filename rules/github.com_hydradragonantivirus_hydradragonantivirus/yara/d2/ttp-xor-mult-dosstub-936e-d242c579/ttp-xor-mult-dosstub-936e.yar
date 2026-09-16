rule TTP_XOR_MULT_DOSStub_936e {
  strings:
    $key_936e = { c7 06 [2] b3 1e [2] f4 1c [2] b3 0d [2] fd 01 [2] f1 0b [2] e6 00 [2] fd 4e [2] c0 }

  condition:
    any of them
}