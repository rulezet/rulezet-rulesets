rule TTP_XOR_QUAD_CurrentVersionRun_0dec {
  strings:
    $key_0dec = { 5e 83 [2] 7a 8d [2] 51 a1 [2] 7f 83 [2] 6b 98 [2] 64 82 [2] 7a 9f [2] 78 9e [2] 63 98 [2] 7f 9f [2] 63 b0 }

  condition:
    any of them
}