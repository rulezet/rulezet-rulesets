rule TTP_XOR_MULT_DOSStub_2875 {
  strings:
    $key_2875 = { 7c 1d [2] 08 05 [2] 4f 07 [2] 08 16 [2] 46 1a [2] 4a 10 [2] 5d 1b [2] 46 55 [2] 7b }

  condition:
    any of them
}