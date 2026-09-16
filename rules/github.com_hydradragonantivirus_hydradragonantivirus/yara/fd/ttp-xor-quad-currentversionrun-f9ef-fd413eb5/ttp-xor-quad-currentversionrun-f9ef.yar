rule TTP_XOR_QUAD_CurrentVersionRun_f9ef {
  strings:
    $key_f9ef = { aa 80 [2] 8e 8e [2] a5 a2 [2] 8b 80 [2] 9f 9b [2] 90 81 [2] 8e 9c [2] 8c 9d [2] 97 9b [2] 8b 9c [2] 97 b3 }

  condition:
    any of them
}