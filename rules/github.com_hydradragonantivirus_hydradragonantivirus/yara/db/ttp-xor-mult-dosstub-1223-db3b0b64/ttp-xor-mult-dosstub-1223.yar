rule TTP_XOR_MULT_DOSStub_1223 {
  strings:
    $key_1223 = { 46 4b [2] 32 53 [2] 75 51 [2] 32 40 [2] 7c 4c [2] 70 46 [2] 67 4d [2] 7c 03 [2] 41 }

  condition:
    any of them
}