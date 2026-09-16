rule TTP_XOR_MULT_DOSStub_57ed {
  strings:
    $key_57ed = { 03 85 [2] 77 9d [2] 30 9f [2] 77 8e [2] 39 82 [2] 35 88 [2] 22 83 [2] 39 cd [2] 04 }

  condition:
    any of them
}