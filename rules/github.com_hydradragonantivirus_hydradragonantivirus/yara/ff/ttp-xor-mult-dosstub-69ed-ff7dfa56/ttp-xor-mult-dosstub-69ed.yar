rule TTP_XOR_MULT_DOSStub_69ed {
  strings:
    $key_69ed = { 3d 85 [2] 49 9d [2] 0e 9f [2] 49 8e [2] 07 82 [2] 0b 88 [2] 1c 83 [2] 07 cd [2] 3a }

  condition:
    any of them
}