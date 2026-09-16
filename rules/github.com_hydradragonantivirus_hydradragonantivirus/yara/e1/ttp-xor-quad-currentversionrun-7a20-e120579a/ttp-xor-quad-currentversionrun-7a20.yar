rule TTP_XOR_QUAD_CurrentVersionRun_7a20 {
  strings:
    $key_7a20 = { 29 4f [2] 0d 41 [2] 26 6d [2] 08 4f [2] 1c 54 [2] 13 4e [2] 0d 53 [2] 0f 52 [2] 14 54 [2] 08 53 [2] 14 7c }

  condition:
    any of them
}