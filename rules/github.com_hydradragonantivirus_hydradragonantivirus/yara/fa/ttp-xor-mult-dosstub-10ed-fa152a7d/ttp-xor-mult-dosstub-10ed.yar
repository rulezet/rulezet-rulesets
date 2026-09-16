rule TTP_XOR_MULT_DOSStub_10ed {
  strings:
    $key_10ed = { 44 85 [2] 30 9d [2] 77 9f [2] 30 8e [2] 7e 82 [2] 72 88 [2] 65 83 [2] 7e cd [2] 43 }

  condition:
    any of them
}