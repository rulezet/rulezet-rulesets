rule TTP_XOR_QUAD_CurrentVersionRun_e2e0 {
  strings:
    $key_e2e0 = { b1 8f [2] 95 81 [2] be ad [2] 90 8f [2] 84 94 [2] 8b 8e [2] 95 93 [2] 97 92 [2] 8c 94 [2] 90 93 [2] 8c bc }

  condition:
    any of them
}