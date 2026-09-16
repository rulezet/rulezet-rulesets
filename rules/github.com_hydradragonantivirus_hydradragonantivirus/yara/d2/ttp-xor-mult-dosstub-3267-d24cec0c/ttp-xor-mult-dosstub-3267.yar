rule TTP_XOR_MULT_DOSStub_3267 {
  strings:
    $key_3267 = { 66 0f [2] 12 17 [2] 55 15 [2] 12 04 [2] 5c 08 [2] 50 02 [2] 47 09 [2] 5c 47 [2] 61 }

  condition:
    any of them
}