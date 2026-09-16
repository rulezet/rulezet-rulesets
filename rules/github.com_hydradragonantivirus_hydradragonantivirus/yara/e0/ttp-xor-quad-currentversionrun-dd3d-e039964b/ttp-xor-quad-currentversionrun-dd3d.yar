rule TTP_XOR_QUAD_CurrentVersionRun_dd3d {
  strings:
    $key_dd3d = { 8e 52 [2] aa 5c [2] 81 70 [2] af 52 [2] bb 49 [2] b4 53 [2] aa 4e [2] a8 4f [2] b3 49 [2] af 4e [2] b3 61 }

  condition:
    any of them
}