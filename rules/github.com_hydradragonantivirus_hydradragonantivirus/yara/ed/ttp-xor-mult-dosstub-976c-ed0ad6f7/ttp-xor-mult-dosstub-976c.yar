rule TTP_XOR_MULT_DOSStub_976c {
  strings:
    $key_976c = { c3 04 [2] b7 1c [2] f0 1e [2] b7 0f [2] f9 03 [2] f5 09 [2] e2 02 [2] f9 4c [2] c4 }

  condition:
    any of them
}