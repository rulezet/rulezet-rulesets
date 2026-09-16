rule TTP_XOR_MULT_DOSStub_7223 {
  strings:
    $key_7223 = { 26 4b [2] 52 53 [2] 15 51 [2] 52 40 [2] 1c 4c [2] 10 46 [2] 07 4d [2] 1c 03 [2] 21 }

  condition:
    any of them
}