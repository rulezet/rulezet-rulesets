rule TTP_XOR_MULT_DOSStub_3b73 {
  strings:
    $key_3b73 = { 6f 1b [2] 1b 03 [2] 5c 01 [2] 1b 10 [2] 55 1c [2] 59 16 [2] 4e 1d [2] 55 53 [2] 68 }

  condition:
    any of them
}