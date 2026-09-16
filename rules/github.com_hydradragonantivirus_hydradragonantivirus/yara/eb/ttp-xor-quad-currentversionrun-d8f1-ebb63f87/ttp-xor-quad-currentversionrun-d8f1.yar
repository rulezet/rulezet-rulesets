rule TTP_XOR_QUAD_CurrentVersionRun_d8f1 {
  strings:
    $key_d8f1 = { 8b 9e [2] af 90 [2] 84 bc [2] aa 9e [2] be 85 [2] b1 9f [2] af 82 [2] ad 83 [2] b6 85 [2] aa 82 [2] b6 ad }

  condition:
    any of them
}