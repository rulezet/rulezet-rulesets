rule TTP_XOR_QUAD_CurrentVersionRun_eaf1 {
  strings:
    $key_eaf1 = { b9 9e [2] 9d 90 [2] b6 bc [2] 98 9e [2] 8c 85 [2] 83 9f [2] 9d 82 [2] 9f 83 [2] 84 85 [2] 98 82 [2] 84 ad }

  condition:
    any of them
}