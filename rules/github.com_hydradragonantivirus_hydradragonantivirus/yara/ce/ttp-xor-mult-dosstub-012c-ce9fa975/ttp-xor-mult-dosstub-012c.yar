rule TTP_XOR_MULT_DOSStub_012c {
  strings:
    $key_012c = { 55 44 [2] 21 5c [2] 66 5e [2] 21 4f [2] 6f 43 [2] 63 49 [2] 74 42 [2] 6f 0c [2] 52 }

  condition:
    any of them
}