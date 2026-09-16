rule TTP_XOR_QUAD_CurrentVersionRun_da08 {
  strings:
    $key_da08 = { 89 67 [2] ad 69 [2] 86 45 [2] a8 67 [2] bc 7c [2] b3 66 [2] ad 7b [2] af 7a [2] b4 7c [2] a8 7b [2] b4 54 }

  condition:
    any of them
}