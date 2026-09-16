rule TTP_XOR_QUAD_CurrentVersionRun_0d3a {
  strings:
    $key_0d3a = { 5e 55 [2] 7a 5b [2] 51 77 [2] 7f 55 [2] 6b 4e [2] 64 54 [2] 7a 49 [2] 78 48 [2] 63 4e [2] 7f 49 [2] 63 66 }

  condition:
    any of them
}