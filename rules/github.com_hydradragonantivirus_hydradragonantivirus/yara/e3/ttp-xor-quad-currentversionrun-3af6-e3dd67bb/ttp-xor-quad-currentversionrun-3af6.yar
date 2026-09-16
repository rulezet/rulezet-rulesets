rule TTP_XOR_QUAD_CurrentVersionRun_3af6 {
  strings:
    $key_3af6 = { 69 99 [2] 4d 97 [2] 66 bb [2] 48 99 [2] 5c 82 [2] 53 98 [2] 4d 85 [2] 4f 84 [2] 54 82 [2] 48 85 [2] 54 aa }

  condition:
    any of them
}