rule TTP_XOR_MULT_DOSStub_3823 {
  strings:
    $key_3823 = { 6c 4b [2] 18 53 [2] 5f 51 [2] 18 40 [2] 56 4c [2] 5a 46 [2] 4d 4d [2] 56 03 [2] 6b }

  condition:
    any of them
}