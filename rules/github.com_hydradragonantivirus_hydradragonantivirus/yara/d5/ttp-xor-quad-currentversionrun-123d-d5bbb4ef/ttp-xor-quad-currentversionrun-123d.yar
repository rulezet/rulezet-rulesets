rule TTP_XOR_QUAD_CurrentVersionRun_123d {
  strings:
    $key_123d = { 41 52 [2] 65 5c [2] 4e 70 [2] 60 52 [2] 74 49 [2] 7b 53 [2] 65 4e [2] 67 4f [2] 7c 49 [2] 60 4e [2] 7c 61 }

  condition:
    any of them
}