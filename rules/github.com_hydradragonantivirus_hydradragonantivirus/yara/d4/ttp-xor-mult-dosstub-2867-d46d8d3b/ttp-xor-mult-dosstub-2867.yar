rule TTP_XOR_MULT_DOSStub_2867 {
  strings:
    $key_2867 = { 7c 0f [2] 08 17 [2] 4f 15 [2] 08 04 [2] 46 08 [2] 4a 02 [2] 5d 09 [2] 46 47 [2] 7b }

  condition:
    any of them
}