rule TTP_XOR_MULT_DOSStub_2826 {
  strings:
    $key_2826 = { 7c 4e [2] 08 56 [2] 4f 54 [2] 08 45 [2] 46 49 [2] 4a 43 [2] 5d 48 [2] 46 06 [2] 7b }

  condition:
    any of them
}