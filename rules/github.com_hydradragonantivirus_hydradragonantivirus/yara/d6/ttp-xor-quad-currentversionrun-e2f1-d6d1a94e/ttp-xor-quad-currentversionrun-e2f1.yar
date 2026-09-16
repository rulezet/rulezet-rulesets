rule TTP_XOR_QUAD_CurrentVersionRun_e2f1 {
  strings:
    $key_e2f1 = { b1 9e [2] 95 90 [2] be bc [2] 90 9e [2] 84 85 [2] 8b 9f [2] 95 82 [2] 97 83 [2] 8c 85 [2] 90 82 [2] 8c ad }

  condition:
    any of them
}