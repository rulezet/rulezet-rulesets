rule TTP_XOR_MULT_DOSStub_4ea2 {
  strings:
    $key_4ea2 = { 1a ca [2] 6e d2 [2] 29 d0 [2] 6e c1 [2] 20 cd [2] 2c c7 [2] 3b cc [2] 20 82 [2] 1d }

  condition:
    any of them
}