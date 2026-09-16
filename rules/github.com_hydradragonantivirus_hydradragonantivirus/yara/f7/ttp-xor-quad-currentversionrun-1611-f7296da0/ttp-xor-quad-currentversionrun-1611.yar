rule TTP_XOR_QUAD_CurrentVersionRun_1611 {
  strings:
    $key_1611 = { 45 7e [2] 61 70 [2] 4a 5c [2] 64 7e [2] 70 65 [2] 7f 7f [2] 61 62 [2] 63 63 [2] 78 65 [2] 64 62 [2] 78 4d }

  condition:
    any of them
}