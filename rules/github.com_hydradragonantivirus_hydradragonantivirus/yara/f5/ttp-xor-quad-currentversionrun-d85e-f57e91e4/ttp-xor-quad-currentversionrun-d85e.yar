rule TTP_XOR_QUAD_CurrentVersionRun_d85e {
  strings:
    $key_d85e = { 8b 31 [2] af 3f [2] 84 13 [2] aa 31 [2] be 2a [2] b1 30 [2] af 2d [2] ad 2c [2] b6 2a [2] aa 2d [2] b6 02 }

  condition:
    any of them
}