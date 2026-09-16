rule TTP_XOR_MULT_DOSStub_2716 {
  strings:
    $key_2716 = { 73 7e [2] 07 66 [2] 40 64 [2] 07 75 [2] 49 79 [2] 45 73 [2] 52 78 [2] 49 36 [2] 74 }

  condition:
    any of them
}