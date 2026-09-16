rule TTP_XOR_MULT_DOSStub_aded {
  strings:
    $key_aded = { f9 85 [2] 8d 9d [2] ca 9f [2] 8d 8e [2] c3 82 [2] cf 88 [2] d8 83 [2] c3 cd [2] fe }

  condition:
    any of them
}