rule TTP_XOR_QUAD_CurrentVersionRun_d829 {
  strings:
    $key_d829 = { 8b 46 [2] af 48 [2] 84 64 [2] aa 46 [2] be 5d [2] b1 47 [2] af 5a [2] ad 5b [2] b6 5d [2] aa 5a [2] b6 75 }

  condition:
    any of them
}