rule TTP_XOR_QUAD_CurrentVersionRun_2611 {
  strings:
    $key_2611 = { 75 7e [2] 51 70 [2] 7a 5c [2] 54 7e [2] 40 65 [2] 4f 7f [2] 51 62 [2] 53 63 [2] 48 65 [2] 54 62 [2] 48 4d }

  condition:
    any of them
}