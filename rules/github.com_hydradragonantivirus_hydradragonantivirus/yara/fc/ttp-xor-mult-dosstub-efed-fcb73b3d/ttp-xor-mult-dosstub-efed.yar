rule TTP_XOR_MULT_DOSStub_efed {
  strings:
    $key_efed = { bb 85 [2] cf 9d [2] 88 9f [2] cf 8e [2] 81 82 [2] 8d 88 [2] 9a 83 [2] 81 cd [2] bc }

  condition:
    any of them
}