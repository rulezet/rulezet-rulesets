rule TTP_XOR_MULT_DOSStub_5b6c {
  strings:
    $key_5b6c = { 0f 04 [2] 7b 1c [2] 3c 1e [2] 7b 0f [2] 35 03 [2] 39 09 [2] 2e 02 [2] 35 4c [2] 08 }

  condition:
    any of them
}