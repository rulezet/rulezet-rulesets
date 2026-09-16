rule TTP_XOR_MULT_DOSStub_066c {
  strings:
    $key_066c = { 52 04 [2] 26 1c [2] 61 1e [2] 26 0f [2] 68 03 [2] 64 09 [2] 73 02 [2] 68 4c [2] 55 }

  condition:
    any of them
}