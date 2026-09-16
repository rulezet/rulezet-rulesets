rule TTP_XOR_QUAD_CurrentVersionRun_da2a {
  strings:
    $key_da2a = { 89 45 [2] ad 4b [2] 86 67 [2] a8 45 [2] bc 5e [2] b3 44 [2] ad 59 [2] af 58 [2] b4 5e [2] a8 59 [2] b4 76 }

  condition:
    any of them
}