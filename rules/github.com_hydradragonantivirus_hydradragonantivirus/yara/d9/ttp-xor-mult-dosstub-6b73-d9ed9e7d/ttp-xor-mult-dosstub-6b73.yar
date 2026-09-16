rule TTP_XOR_MULT_DOSStub_6b73 {
  strings:
    $key_6b73 = { 3f 1b [2] 4b 03 [2] 0c 01 [2] 4b 10 [2] 05 1c [2] 09 16 [2] 1e 1d [2] 05 53 [2] 38 }

  condition:
    any of them
}