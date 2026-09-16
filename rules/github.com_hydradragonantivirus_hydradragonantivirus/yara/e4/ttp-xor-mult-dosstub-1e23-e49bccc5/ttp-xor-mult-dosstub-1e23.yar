rule TTP_XOR_MULT_DOSStub_1e23 {
  strings:
    $key_1e23 = { 4a 4b [2] 3e 53 [2] 79 51 [2] 3e 40 [2] 70 4c [2] 7c 46 [2] 6b 4d [2] 70 03 [2] 4d }

  condition:
    any of them
}