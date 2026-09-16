rule TTP_XOR_MULT_DOSStub_f8ff {
  strings:
    $key_f8ff = { ac 97 [2] d8 8f [2] 9f 8d [2] d8 9c [2] 96 90 [2] 9a 9a [2] 8d 91 [2] 96 df [2] ab }

  condition:
    any of them
}