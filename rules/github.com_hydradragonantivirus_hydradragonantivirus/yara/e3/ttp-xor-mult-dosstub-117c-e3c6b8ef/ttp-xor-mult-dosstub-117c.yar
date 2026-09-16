rule TTP_XOR_MULT_DOSStub_117c {
  strings:
    $key_117c = { 45 14 [2] 31 0c [2] 76 0e [2] 31 1f [2] 7f 13 [2] 73 19 [2] 64 12 [2] 7f 5c [2] 42 }

  condition:
    any of them
}