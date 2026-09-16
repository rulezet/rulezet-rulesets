rule TTP_XOR_QUAD_CurrentVersionRun_d868 {
  strings:
    $key_d868 = { 8b 07 [2] af 09 [2] 84 25 [2] aa 07 [2] be 1c [2] b1 06 [2] af 1b [2] ad 1a [2] b6 1c [2] aa 1b [2] b6 34 }

  condition:
    any of them
}