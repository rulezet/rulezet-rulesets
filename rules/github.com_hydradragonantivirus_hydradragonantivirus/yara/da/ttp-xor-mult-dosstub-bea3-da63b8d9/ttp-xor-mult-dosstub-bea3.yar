rule TTP_XOR_MULT_DOSStub_bea3 {
  strings:
    $key_bea3 = { ea cb [2] 9e d3 [2] d9 d1 [2] 9e c0 [2] d0 cc [2] dc c6 [2] cb cd [2] d0 83 [2] ed }

  condition:
    any of them
}