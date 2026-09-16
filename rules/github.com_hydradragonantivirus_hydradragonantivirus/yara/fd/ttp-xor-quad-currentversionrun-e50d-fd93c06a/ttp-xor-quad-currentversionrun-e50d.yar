rule TTP_XOR_QUAD_CurrentVersionRun_e50d {
  strings:
    $key_e50d = { b6 62 [2] 92 6c [2] b9 40 [2] 97 62 [2] 83 79 [2] 8c 63 [2] 92 7e [2] 90 7f [2] 8b 79 [2] 97 7e [2] 8b 51 }

  condition:
    any of them
}