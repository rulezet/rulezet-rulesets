rule TTP_XOR_MULT_DOSStub_f80e {
  strings:
    $key_f80e = { ac 66 [2] d8 7e [2] 9f 7c [2] d8 6d [2] 96 61 [2] 9a 6b [2] 8d 60 [2] 96 2e [2] ab }

  condition:
    any of them
}