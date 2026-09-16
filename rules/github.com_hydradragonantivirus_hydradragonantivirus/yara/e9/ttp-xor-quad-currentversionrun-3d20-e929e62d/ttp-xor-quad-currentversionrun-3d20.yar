rule TTP_XOR_QUAD_CurrentVersionRun_3d20 {
  strings:
    $key_3d20 = { 6e 4f [2] 4a 41 [2] 61 6d [2] 4f 4f [2] 5b 54 [2] 54 4e [2] 4a 53 [2] 48 52 [2] 53 54 [2] 4f 53 [2] 53 7c }

  condition:
    any of them
}