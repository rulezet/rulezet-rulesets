rule TTP_XOR_QUAD_CurrentVersionRun_fff1 {
  strings:
    $key_fff1 = { ac 9e [2] 88 90 [2] a3 bc [2] 8d 9e [2] 99 85 [2] 96 9f [2] 88 82 [2] 8a 83 [2] 91 85 [2] 8d 82 [2] 91 ad }

  condition:
    any of them
}