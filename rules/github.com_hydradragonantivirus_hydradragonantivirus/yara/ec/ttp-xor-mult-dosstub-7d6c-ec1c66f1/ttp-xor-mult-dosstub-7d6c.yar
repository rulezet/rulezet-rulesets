rule TTP_XOR_MULT_DOSStub_7d6c {
  strings:
    $key_7d6c = { 29 04 [2] 5d 1c [2] 1a 1e [2] 5d 0f [2] 13 03 [2] 1f 09 [2] 08 02 [2] 13 4c [2] 2e }

  condition:
    any of them
}