rule TTP_XOR_QUAD_CurrentVersionRun_d807 {
  strings:
    $key_d807 = { 8b 68 [2] af 66 [2] 84 4a [2] aa 68 [2] be 73 [2] b1 69 [2] af 74 [2] ad 75 [2] b6 73 [2] aa 74 [2] b6 5b }

  condition:
    any of them
}