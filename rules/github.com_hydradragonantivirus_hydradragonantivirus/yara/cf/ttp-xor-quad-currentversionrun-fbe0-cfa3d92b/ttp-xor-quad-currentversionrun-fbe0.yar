rule TTP_XOR_QUAD_CurrentVersionRun_fbe0 {
  strings:
    $key_fbe0 = { a8 8f [2] 8c 81 [2] a7 ad [2] 89 8f [2] 9d 94 [2] 92 8e [2] 8c 93 [2] 8e 92 [2] 95 94 [2] 89 93 [2] 95 bc }

  condition:
    any of them
}