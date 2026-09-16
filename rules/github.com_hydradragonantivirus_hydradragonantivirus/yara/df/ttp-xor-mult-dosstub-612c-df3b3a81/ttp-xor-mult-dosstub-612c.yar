rule TTP_XOR_MULT_DOSStub_612c {
  strings:
    $key_612c = { 35 44 [2] 41 5c [2] 06 5e [2] 41 4f [2] 0f 43 [2] 03 49 [2] 14 42 [2] 0f 0c [2] 32 }

  condition:
    any of them
}