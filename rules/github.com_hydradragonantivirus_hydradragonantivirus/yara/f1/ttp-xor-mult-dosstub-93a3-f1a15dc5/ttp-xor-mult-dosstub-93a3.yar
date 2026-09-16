rule TTP_XOR_MULT_DOSStub_93a3 {
  strings:
    $key_93a3 = { c7 cb [2] b3 d3 [2] f4 d1 [2] b3 c0 [2] fd cc [2] f1 c6 [2] e6 cd [2] fd 83 [2] c0 }

  condition:
    any of them
}