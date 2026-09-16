rule TTP_XOR_MULT_DOSStub_2aae {
  strings:
    $key_2aae = { 7e c6 [2] 0a de [2] 4d dc [2] 0a cd [2] 44 c1 [2] 48 cb [2] 5f c0 [2] 44 8e [2] 79 }

  condition:
    any of them
}