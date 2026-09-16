rule TTP_XOR_MULT_DOSStub_11d1 {
  strings:
    $key_11d1 = { 45 b9 [2] 31 a1 [2] 76 a3 [2] 31 b2 [2] 7f be [2] 73 b4 [2] 64 bf [2] 7f f1 [2] 42 }

  condition:
    any of them
}