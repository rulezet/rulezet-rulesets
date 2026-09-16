rule TTP_XOR_MULT_DOSStub_ef2b {
  strings:
    $key_ef2b = { bb 43 [2] cf 5b [2] 88 59 [2] cf 48 [2] 81 44 [2] 8d 4e [2] 9a 45 [2] 81 0b [2] bc }

  condition:
    any of them
}