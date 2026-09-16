rule TTP_XOR_MULT_DOSStub_272e {
  strings:
    $key_272e = { 73 46 [2] 07 5e [2] 40 5c [2] 07 4d [2] 49 41 [2] 45 4b [2] 52 40 [2] 49 0e [2] 74 }

  condition:
    any of them
}