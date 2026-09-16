rule TTP_XOR_QUAD_CurrentVersionRun_0600 {
  strings:
    $key_0600 = { 55 6f [2] 71 61 [2] 5a 4d [2] 74 6f [2] 60 74 [2] 6f 6e [2] 71 73 [2] 73 72 [2] 68 74 [2] 74 73 [2] 68 5c }

  condition:
    any of them
}