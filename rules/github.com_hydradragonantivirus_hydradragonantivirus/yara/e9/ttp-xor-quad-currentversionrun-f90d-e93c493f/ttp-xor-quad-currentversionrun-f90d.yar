rule TTP_XOR_QUAD_CurrentVersionRun_f90d {
  strings:
    $key_f90d = { aa 62 [2] 8e 6c [2] a5 40 [2] 8b 62 [2] 9f 79 [2] 90 63 [2] 8e 7e [2] 8c 7f [2] 97 79 [2] 8b 7e [2] 97 51 }

  condition:
    any of them
}