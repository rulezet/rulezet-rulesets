rule TTP_XOR_QUAD_CurrentVersionRun_d8ff {
  strings:
    $key_d8ff = { 8b 90 [2] af 9e [2] 84 b2 [2] aa 90 [2] be 8b [2] b1 91 [2] af 8c [2] ad 8d [2] b6 8b [2] aa 8c [2] b6 a3 }

  condition:
    any of them
}