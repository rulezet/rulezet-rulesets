rule TTP_XOR_MULT_DOSStub_216c {
  strings:
    $key_216c = { 75 04 [2] 01 1c [2] 46 1e [2] 01 0f [2] 4f 03 [2] 43 09 [2] 54 02 [2] 4f 4c [2] 72 }

  condition:
    any of them
}