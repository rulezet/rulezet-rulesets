rule TTP_XOR_MULT_DOSStub_e897 {
  strings:
    $key_e897 = { bc ff [2] c8 e7 [2] 8f e5 [2] c8 f4 [2] 86 f8 [2] 8a f2 [2] 9d f9 [2] 86 b7 [2] bb }

  condition:
    any of them
}