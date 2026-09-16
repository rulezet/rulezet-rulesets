rule TTP_XOR_MULT_DOSStub_ffb0 {
  strings:
    $key_ffb0 = { ab d8 [2] df c0 [2] 98 c2 [2] df d3 [2] 91 df [2] 9d d5 [2] 8a de [2] 91 90 [2] ac }

  condition:
    any of them
}