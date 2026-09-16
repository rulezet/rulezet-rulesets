rule TTP_XOR_MULT_DOSStub_87ed {
  strings:
    $key_87ed = { d3 85 [2] a7 9d [2] e0 9f [2] a7 8e [2] e9 82 [2] e5 88 [2] f2 83 [2] e9 cd [2] d4 }

  condition:
    any of them
}