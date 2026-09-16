rule TTP_XOR_MULT_DOSStub_c2bd {
  strings:
    $key_c2bd = { 96 d5 [2] e2 cd [2] a5 cf [2] e2 de [2] ac d2 [2] a0 d8 [2] b7 d3 [2] ac 9d [2] 91 }

  condition:
    any of them
}