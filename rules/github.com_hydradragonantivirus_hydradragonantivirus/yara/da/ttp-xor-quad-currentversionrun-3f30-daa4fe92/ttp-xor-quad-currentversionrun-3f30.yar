rule TTP_XOR_QUAD_CurrentVersionRun_3f30 {
  strings:
    $key_3f30 = { 6c 5f [2] 48 51 [2] 63 7d [2] 4d 5f [2] 59 44 [2] 56 5e [2] 48 43 [2] 4a 42 [2] 51 44 [2] 4d 43 [2] 51 6c }

  condition:
    any of them
}