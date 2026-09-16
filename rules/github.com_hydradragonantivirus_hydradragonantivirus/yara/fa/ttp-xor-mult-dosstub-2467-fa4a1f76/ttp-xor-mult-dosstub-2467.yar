rule TTP_XOR_MULT_DOSStub_2467 {
  strings:
    $key_2467 = { 70 0f [2] 04 17 [2] 43 15 [2] 04 04 [2] 4a 08 [2] 46 02 [2] 51 09 [2] 4a 47 [2] 77 }

  condition:
    any of them
}