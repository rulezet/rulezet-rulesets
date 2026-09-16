rule TTP_XOR_MULT_DOSStub_666c {
  strings:
    $key_666c = { 32 04 [2] 46 1c [2] 01 1e [2] 46 0f [2] 08 03 [2] 04 09 [2] 13 02 [2] 08 4c [2] 35 }

  condition:
    any of them
}