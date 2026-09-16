rule TTP_XOR_MULT_DOSStub_1ea2 {
  strings:
    $key_1ea2 = { 4a ca [2] 3e d2 [2] 79 d0 [2] 3e c1 [2] 70 cd [2] 7c c7 [2] 6b cc [2] 70 82 [2] 4d }

  condition:
    any of them
}