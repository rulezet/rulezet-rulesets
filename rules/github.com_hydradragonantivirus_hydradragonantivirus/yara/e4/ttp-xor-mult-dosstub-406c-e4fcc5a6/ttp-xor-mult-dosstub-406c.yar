rule TTP_XOR_MULT_DOSStub_406c {
  strings:
    $key_406c = { 14 04 [2] 60 1c [2] 27 1e [2] 60 0f [2] 2e 03 [2] 22 09 [2] 35 02 [2] 2e 4c [2] 13 }

  condition:
    any of them
}