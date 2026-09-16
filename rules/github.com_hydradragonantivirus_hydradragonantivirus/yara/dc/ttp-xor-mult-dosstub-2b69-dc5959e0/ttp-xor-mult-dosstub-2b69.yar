rule TTP_XOR_MULT_DOSStub_2b69 {
  strings:
    $key_2b69 = { 7f 01 [2] 0b 19 [2] 4c 1b [2] 0b 0a [2] 45 06 [2] 49 0c [2] 5e 07 [2] 45 49 [2] 78 }

  condition:
    any of them
}