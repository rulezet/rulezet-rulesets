rule TTP_XOR_MULT_DOSStub_3167 {
  strings:
    $key_3167 = { 65 0f [2] 11 17 [2] 56 15 [2] 11 04 [2] 5f 08 [2] 53 02 [2] 44 09 [2] 5f 47 [2] 62 }

  condition:
    any of them
}