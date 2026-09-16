rule TTP_XOR_MULT_DOSStub_832d {
  strings:
    $key_832d = { d7 45 [2] a3 5d [2] e4 5f [2] a3 4e [2] ed 42 [2] e1 48 [2] f6 43 [2] ed 0d [2] d0 }

  condition:
    any of them
}