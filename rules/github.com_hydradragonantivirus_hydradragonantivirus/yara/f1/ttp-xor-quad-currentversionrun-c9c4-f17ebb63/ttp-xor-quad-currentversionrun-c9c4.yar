rule TTP_XOR_QUAD_CurrentVersionRun_c9c4 {
  strings:
    $key_c9c4 = { 9a ab [2] be a5 [2] 95 89 [2] bb ab [2] af b0 [2] a0 aa [2] be b7 [2] bc b6 [2] a7 b0 [2] bb b7 [2] a7 98 }

  condition:
    any of them
}