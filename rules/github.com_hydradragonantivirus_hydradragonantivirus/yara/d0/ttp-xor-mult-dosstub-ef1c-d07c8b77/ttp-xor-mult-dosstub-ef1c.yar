rule TTP_XOR_MULT_DOSStub_ef1c {
  strings:
    $key_ef1c = { bb 74 [2] cf 6c [2] 88 6e [2] cf 7f [2] 81 73 [2] 8d 79 [2] 9a 72 [2] 81 3c [2] bc }

  condition:
    any of them
}