rule TTP_XOR_MULT_DOSStub_2bae {
  strings:
    $key_2bae = { 7f c6 [2] 0b de [2] 4c dc [2] 0b cd [2] 45 c1 [2] 49 cb [2] 5e c0 [2] 45 8e [2] 78 }

  condition:
    any of them
}