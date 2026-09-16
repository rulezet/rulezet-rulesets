rule TTP_XOR_MULT_DOSStub_1d29 {
  strings:
    $key_1d29 = { 49 41 [2] 3d 59 [2] 7a 5b [2] 3d 4a [2] 73 46 [2] 7f 4c [2] 68 47 [2] 73 09 [2] 4e }

  condition:
    any of them
}