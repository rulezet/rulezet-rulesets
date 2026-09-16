rule TTP_XOR_MULT_DOSStub_d9bd {
  strings:
    $key_d9bd = { 8d d5 [2] f9 cd [2] be cf [2] f9 de [2] b7 d2 [2] bb d8 [2] ac d3 [2] b7 9d [2] 8a }

  condition:
    any of them
}