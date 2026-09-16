rule TTP_XOR_MULT_DOSStub_5ba8 {
  strings:
    $key_5ba8 = { 0f c0 [2] 7b d8 [2] 3c da [2] 7b cb [2] 35 c7 [2] 39 cd [2] 2e c6 [2] 35 88 [2] 08 }

  condition:
    any of them
}