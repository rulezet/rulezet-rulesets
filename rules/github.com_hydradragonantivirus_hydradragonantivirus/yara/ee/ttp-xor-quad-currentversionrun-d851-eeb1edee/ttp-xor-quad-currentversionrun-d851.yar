rule TTP_XOR_QUAD_CurrentVersionRun_d851 {
  strings:
    $key_d851 = { 8b 3e [2] af 30 [2] 84 1c [2] aa 3e [2] be 25 [2] b1 3f [2] af 22 [2] ad 23 [2] b6 25 [2] aa 22 [2] b6 0d }

  condition:
    any of them
}