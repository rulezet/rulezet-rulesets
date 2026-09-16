rule TTP_XOR_MULT_DOSStub_3aae {
  strings:
    $key_3aae = { 6e c6 [2] 1a de [2] 5d dc [2] 1a cd [2] 54 c1 [2] 58 cb [2] 4f c0 [2] 54 8e [2] 69 }

  condition:
    any of them
}