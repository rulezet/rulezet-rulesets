rule TTP_XOR_MULT_DOSStub_d06c {
  strings:
    $key_d06c = { 84 04 [2] f0 1c [2] b7 1e [2] f0 0f [2] be 03 [2] b2 09 [2] a5 02 [2] be 4c [2] 83 }

  condition:
    any of them
}