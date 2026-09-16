rule TTP_XOR_QUAD_CurrentVersionRun_f94f {
  strings:
    $key_f94f = { aa 20 [2] 8e 2e [2] a5 02 [2] 8b 20 [2] 9f 3b [2] 90 21 [2] 8e 3c [2] 8c 3d [2] 97 3b [2] 8b 3c [2] 97 13 }

  condition:
    any of them
}