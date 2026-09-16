rule TTP_XOR_QUAD_CurrentVersionRun_d826 {
  strings:
    $key_d826 = { 8b 49 [2] af 47 [2] 84 6b [2] aa 49 [2] be 52 [2] b1 48 [2] af 55 [2] ad 54 [2] b6 52 [2] aa 55 [2] b6 7a }

  condition:
    any of them
}