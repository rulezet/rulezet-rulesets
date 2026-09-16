rule TTP_XOR_MULT_DOSStub_f826 {
  strings:
    $key_f826 = { ac 4e [2] d8 56 [2] 9f 54 [2] d8 45 [2] 96 49 [2] 9a 43 [2] 8d 48 [2] 96 06 [2] ab }

  condition:
    any of them
}