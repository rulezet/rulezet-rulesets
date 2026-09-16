rule TTP_XOR_QUAD_CurrentVersionRun_e52f {
  strings:
    $key_e52f = { b6 40 [2] 92 4e [2] b9 62 [2] 97 40 [2] 83 5b [2] 8c 41 [2] 92 5c [2] 90 5d [2] 8b 5b [2] 97 5c [2] 8b 73 }

  condition:
    any of them
}