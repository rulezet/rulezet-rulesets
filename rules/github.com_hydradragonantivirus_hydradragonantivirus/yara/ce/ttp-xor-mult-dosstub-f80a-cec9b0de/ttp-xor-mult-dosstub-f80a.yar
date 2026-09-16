rule TTP_XOR_MULT_DOSStub_f80a {
  strings:
    $key_f80a = { ac 62 [2] d8 7a [2] 9f 78 [2] d8 69 [2] 96 65 [2] 9a 6f [2] 8d 64 [2] 96 2a [2] ab }

  condition:
    any of them
}