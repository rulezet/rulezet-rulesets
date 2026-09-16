rule TTP_XOR_QUAD_CurrentVersionRun_da88 {
  strings:
    $key_da88 = { 89 e7 [2] ad e9 [2] 86 c5 [2] a8 e7 [2] bc fc [2] b3 e6 [2] ad fb [2] af fa [2] b4 fc [2] a8 fb [2] b4 d4 }

  condition:
    any of them
}