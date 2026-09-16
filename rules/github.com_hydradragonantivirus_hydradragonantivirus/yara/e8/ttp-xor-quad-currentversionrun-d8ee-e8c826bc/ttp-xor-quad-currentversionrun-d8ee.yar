rule TTP_XOR_QUAD_CurrentVersionRun_d8ee {
  strings:
    $key_d8ee = { 8b 81 [2] af 8f [2] 84 a3 [2] aa 81 [2] be 9a [2] b1 80 [2] af 9d [2] ad 9c [2] b6 9a [2] aa 9d [2] b6 b2 }

  condition:
    any of them
}