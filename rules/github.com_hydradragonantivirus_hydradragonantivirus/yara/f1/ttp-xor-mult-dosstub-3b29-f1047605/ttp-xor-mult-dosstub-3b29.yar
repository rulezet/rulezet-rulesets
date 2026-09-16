rule TTP_XOR_MULT_DOSStub_3b29 {
  strings:
    $key_3b29 = { 6f 41 [2] 1b 59 [2] 5c 5b [2] 1b 4a [2] 55 46 [2] 59 4c [2] 4e 47 [2] 55 09 [2] 68 }

  condition:
    any of them
}