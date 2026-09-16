rule TTP_XOR_MULT_DOSStub_2861 {
  strings:
    $key_2861 = { 7c 09 [2] 08 11 [2] 4f 13 [2] 08 02 [2] 46 0e [2] 4a 04 [2] 5d 0f [2] 46 41 [2] 7b }

  condition:
    any of them
}