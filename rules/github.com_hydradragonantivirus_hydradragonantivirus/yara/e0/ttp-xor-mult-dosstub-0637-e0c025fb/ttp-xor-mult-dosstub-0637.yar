rule TTP_XOR_MULT_DOSStub_0637 {
  strings:
    $key_0637 = { 52 5f [2] 26 47 [2] 61 45 [2] 26 54 [2] 68 58 [2] 64 52 [2] 73 59 [2] 68 17 [2] 55 }

  condition:
    any of them
}