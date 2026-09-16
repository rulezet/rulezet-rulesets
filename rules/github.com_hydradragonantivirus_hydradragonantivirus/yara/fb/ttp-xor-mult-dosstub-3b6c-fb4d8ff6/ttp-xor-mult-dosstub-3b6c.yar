rule TTP_XOR_MULT_DOSStub_3b6c {
  strings:
    $key_3b6c = { 6f 04 [2] 1b 1c [2] 5c 1e [2] 1b 0f [2] 55 03 [2] 59 09 [2] 4e 02 [2] 55 4c [2] 68 }

  condition:
    any of them
}