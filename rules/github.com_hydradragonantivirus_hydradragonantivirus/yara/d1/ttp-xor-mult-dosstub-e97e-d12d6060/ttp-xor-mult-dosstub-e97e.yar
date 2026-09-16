rule TTP_XOR_MULT_DOSStub_e97e {
  strings:
    $key_e97e = { bd 16 [2] c9 0e [2] 8e 0c [2] c9 1d [2] 87 11 [2] 8b 1b [2] 9c 10 [2] 87 5e [2] ba }

  condition:
    any of them
}