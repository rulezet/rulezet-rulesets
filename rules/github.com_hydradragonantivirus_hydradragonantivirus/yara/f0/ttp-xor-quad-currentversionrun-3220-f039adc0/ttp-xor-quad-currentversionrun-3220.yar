rule TTP_XOR_QUAD_CurrentVersionRun_3220 {
  strings:
    $key_3220 = { 61 4f [2] 45 41 [2] 6e 6d [2] 40 4f [2] 54 54 [2] 5b 4e [2] 45 53 [2] 47 52 [2] 5c 54 [2] 40 53 [2] 5c 7c }

  condition:
    any of them
}