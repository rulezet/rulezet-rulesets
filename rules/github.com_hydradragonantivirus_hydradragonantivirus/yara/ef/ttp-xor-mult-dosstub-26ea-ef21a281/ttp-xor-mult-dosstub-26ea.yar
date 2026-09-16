rule TTP_XOR_MULT_DOSStub_26ea {
  strings:
    $key_26ea = { 72 82 [2] 06 9a [2] 41 98 [2] 06 89 [2] 48 85 [2] 44 8f [2] 53 84 [2] 48 ca [2] 75 }

  condition:
    any of them
}