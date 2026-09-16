rule TTP_XOR_QUAD_CurrentVersionRun_6d11 {
  strings:
    $key_6d11 = { 3e 7e [2] 1a 70 [2] 31 5c [2] 1f 7e [2] 0b 65 [2] 04 7f [2] 1a 62 [2] 18 63 [2] 03 65 [2] 1f 62 [2] 03 4d }

  condition:
    any of them
}