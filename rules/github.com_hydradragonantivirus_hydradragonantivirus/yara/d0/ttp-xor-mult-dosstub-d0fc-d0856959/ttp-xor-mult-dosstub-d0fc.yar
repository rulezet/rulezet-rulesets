rule TTP_XOR_MULT_DOSStub_d0fc {
  strings:
    $key_d0fc = { 84 94 [2] f0 8c [2] b7 8e [2] f0 9f [2] be 93 [2] b2 99 [2] a5 92 [2] be dc [2] 83 }

  condition:
    any of them
}