rule TTP_XOR_MULT_DOSStub_19ed {
  strings:
    $key_19ed = { 4d 85 [2] 39 9d [2] 7e 9f [2] 39 8e [2] 77 82 [2] 7b 88 [2] 6c 83 [2] 77 cd [2] 4a }

  condition:
    any of them
}