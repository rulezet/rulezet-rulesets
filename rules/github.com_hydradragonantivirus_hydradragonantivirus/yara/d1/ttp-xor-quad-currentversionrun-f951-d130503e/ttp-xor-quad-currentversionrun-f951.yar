rule TTP_XOR_QUAD_CurrentVersionRun_f951 {
  strings:
    $key_f951 = { aa 3e [2] 8e 30 [2] a5 1c [2] 8b 3e [2] 9f 25 [2] 90 3f [2] 8e 22 [2] 8c 23 [2] 97 25 [2] 8b 22 [2] 97 0d }

  condition:
    any of them
}