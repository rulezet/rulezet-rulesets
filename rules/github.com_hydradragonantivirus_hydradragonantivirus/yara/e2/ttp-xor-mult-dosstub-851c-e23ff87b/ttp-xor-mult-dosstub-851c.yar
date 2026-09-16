rule TTP_XOR_MULT_DOSStub_851c {
  strings:
    $key_851c = { d1 74 [2] a5 6c [2] e2 6e [2] a5 7f [2] eb 73 [2] e7 79 [2] f0 72 [2] eb 3c [2] d6 }

  condition:
    any of them
}