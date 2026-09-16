rule TTP_XOR_QUAD_CurrentVersionRun_e53c {
  strings:
    $key_e53c = { b6 53 [2] 92 5d [2] b9 71 [2] 97 53 [2] 83 48 [2] 8c 52 [2] 92 4f [2] 90 4e [2] 8b 48 [2] 97 4f [2] 8b 60 }

  condition:
    any of them
}