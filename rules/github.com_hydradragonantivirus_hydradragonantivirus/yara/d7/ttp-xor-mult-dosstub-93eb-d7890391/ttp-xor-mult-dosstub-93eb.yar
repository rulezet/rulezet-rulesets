rule TTP_XOR_MULT_DOSStub_93eb {
  strings:
    $key_93eb = { c7 83 [2] b3 9b [2] f4 99 [2] b3 88 [2] fd 84 [2] f1 8e [2] e6 85 [2] fd cb [2] c0 }

  condition:
    any of them
}