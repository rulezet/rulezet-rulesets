rule TTP_XOR_MULT_DOSStub_79ae {
  strings:
    $key_79ae = { 2d c6 [2] 59 de [2] 1e dc [2] 59 cd [2] 17 c1 [2] 1b cb [2] 0c c0 [2] 17 8e [2] 2a }

  condition:
    any of them
}