rule TTP_XOR_MULT_DOSStub_012e {
  strings:
    $key_012e = { 55 46 [2] 21 5e [2] 66 5c [2] 21 4d [2] 6f 41 [2] 63 4b [2] 74 40 [2] 6f 0e [2] 52 }

  condition:
    any of them
}