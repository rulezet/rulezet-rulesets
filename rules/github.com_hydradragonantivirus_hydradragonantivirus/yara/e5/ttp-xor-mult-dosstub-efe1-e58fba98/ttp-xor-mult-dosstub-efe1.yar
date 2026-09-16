rule TTP_XOR_MULT_DOSStub_efe1 {
  strings:
    $key_efe1 = { bb 89 [2] cf 91 [2] 88 93 [2] cf 82 [2] 81 8e [2] 8d 84 [2] 9a 8f [2] 81 c1 [2] bc }

  condition:
    any of them
}