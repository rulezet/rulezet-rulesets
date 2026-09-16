rule TTP_XOR_QUAD_CurrentVersionRun_143d {
  strings:
    $key_143d = { 47 52 [2] 63 5c [2] 48 70 [2] 66 52 [2] 72 49 [2] 7d 53 [2] 63 4e [2] 61 4f [2] 7a 49 [2] 66 4e [2] 7a 61 }

  condition:
    any of them
}