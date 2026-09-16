rule TTP_XOR_QUAD_CurrentVersionRun_da3d {
  strings:
    $key_da3d = { 89 52 [2] ad 5c [2] 86 70 [2] a8 52 [2] bc 49 [2] b3 53 [2] ad 4e [2] af 4f [2] b4 49 [2] a8 4e [2] b4 61 }

  condition:
    any of them
}