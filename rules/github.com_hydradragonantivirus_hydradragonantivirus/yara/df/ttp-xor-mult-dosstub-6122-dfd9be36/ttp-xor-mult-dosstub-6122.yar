rule TTP_XOR_MULT_DOSStub_6122 {
  strings:
    $key_6122 = { 35 4a [2] 41 52 [2] 06 50 [2] 41 41 [2] 0f 4d [2] 03 47 [2] 14 4c [2] 0f 02 [2] 32 }

  condition:
    any of them
}