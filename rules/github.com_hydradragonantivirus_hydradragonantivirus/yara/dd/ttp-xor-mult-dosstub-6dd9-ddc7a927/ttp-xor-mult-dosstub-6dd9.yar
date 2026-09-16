rule TTP_XOR_MULT_DOSStub_6dd9 {
  strings:
    $key_6dd9 = { 39 b1 [2] 4d a9 [2] 0a ab [2] 4d ba [2] 03 b6 [2] 0f bc [2] 18 b7 [2] 03 f9 [2] 3e }

  condition:
    any of them
}