rule TTP_XOR_QUAD_CurrentVersionRun_1420 {
  strings:
    $key_1420 = { 47 4f [2] 63 41 [2] 48 6d [2] 66 4f [2] 72 54 [2] 7d 4e [2] 63 53 [2] 61 52 [2] 7a 54 [2] 66 53 [2] 7a 7c }

  condition:
    any of them
}