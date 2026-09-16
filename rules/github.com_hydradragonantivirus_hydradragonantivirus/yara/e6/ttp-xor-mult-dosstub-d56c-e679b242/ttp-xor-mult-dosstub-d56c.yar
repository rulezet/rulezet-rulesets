rule TTP_XOR_MULT_DOSStub_d56c {
  strings:
    $key_d56c = { 81 04 [2] f5 1c [2] b2 1e [2] f5 0f [2] bb 03 [2] b7 09 [2] a0 02 [2] bb 4c [2] 86 }

  condition:
    any of them
}