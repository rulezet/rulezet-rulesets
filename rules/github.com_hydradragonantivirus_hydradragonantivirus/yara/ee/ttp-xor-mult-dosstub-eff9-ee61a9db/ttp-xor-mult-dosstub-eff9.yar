rule TTP_XOR_MULT_DOSStub_eff9 {
  strings:
    $key_eff9 = { bb 91 [2] cf 89 [2] 88 8b [2] cf 9a [2] 81 96 [2] 8d 9c [2] 9a 97 [2] 81 d9 [2] bc }

  condition:
    any of them
}