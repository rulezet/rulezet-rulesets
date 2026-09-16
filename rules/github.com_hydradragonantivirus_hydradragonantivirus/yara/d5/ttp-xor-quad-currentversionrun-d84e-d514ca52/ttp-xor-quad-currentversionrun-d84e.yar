rule TTP_XOR_QUAD_CurrentVersionRun_d84e {
  strings:
    $key_d84e = { 8b 21 [2] af 2f [2] 84 03 [2] aa 21 [2] be 3a [2] b1 20 [2] af 3d [2] ad 3c [2] b6 3a [2] aa 3d [2] b6 12 }

  condition:
    any of them
}