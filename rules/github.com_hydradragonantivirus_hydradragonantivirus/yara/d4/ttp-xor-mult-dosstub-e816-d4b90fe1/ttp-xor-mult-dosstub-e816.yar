rule TTP_XOR_MULT_DOSStub_e816 {
  strings:
    $key_e816 = { bc 7e [2] c8 66 [2] 8f 64 [2] c8 75 [2] 86 79 [2] 8a 73 [2] 9d 78 [2] 86 36 [2] bb }

  condition:
    any of them
}