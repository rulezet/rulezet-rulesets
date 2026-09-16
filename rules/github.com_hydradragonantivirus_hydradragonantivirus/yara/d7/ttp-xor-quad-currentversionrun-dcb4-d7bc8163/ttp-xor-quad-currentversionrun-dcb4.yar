rule TTP_XOR_QUAD_CurrentVersionRun_dcb4 {
  strings:
    $key_dcb4 = { 8f db [2] ab d5 [2] 80 f9 [2] ae db [2] ba c0 [2] b5 da [2] ab c7 [2] a9 c6 [2] b2 c0 [2] ae c7 [2] b2 e8 }

  condition:
    any of them
}