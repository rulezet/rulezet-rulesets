rule TTP_XOR_QUAD_CurrentVersionRun_0f00 {
  strings:
    $key_0f00 = { 5c 6f [2] 78 61 [2] 53 4d [2] 7d 6f [2] 69 74 [2] 66 6e [2] 78 73 [2] 7a 72 [2] 61 74 [2] 7d 73 [2] 61 5c }

  condition:
    any of them
}