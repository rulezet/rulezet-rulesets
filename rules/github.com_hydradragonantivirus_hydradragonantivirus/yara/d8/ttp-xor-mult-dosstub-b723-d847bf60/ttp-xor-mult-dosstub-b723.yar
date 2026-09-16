rule TTP_XOR_MULT_DOSStub_b723 {
  strings:
    $key_b723 = { e3 4b [2] 97 53 [2] d0 51 [2] 97 40 [2] d9 4c [2] d5 46 [2] c2 4d [2] d9 03 [2] e4 }

  condition:
    any of them
}