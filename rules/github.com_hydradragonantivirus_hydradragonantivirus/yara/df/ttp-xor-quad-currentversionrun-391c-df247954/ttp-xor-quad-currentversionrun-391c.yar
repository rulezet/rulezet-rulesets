rule TTP_XOR_QUAD_CurrentVersionRun_391c {
  strings:
    $key_391c = { 6a 73 [2] 4e 7d [2] 65 51 [2] 4b 73 [2] 5f 68 [2] 50 72 [2] 4e 6f [2] 4c 6e [2] 57 68 [2] 4b 6f [2] 57 40 }

  condition:
    any of them
}