rule TTP_XOR_QUAD_CurrentVersionRun_6211 {
  strings:
    $key_6211 = { 31 7e [2] 15 70 [2] 3e 5c [2] 10 7e [2] 04 65 [2] 0b 7f [2] 15 62 [2] 17 63 [2] 0c 65 [2] 10 62 [2] 0c 4d }

  condition:
    any of them
}