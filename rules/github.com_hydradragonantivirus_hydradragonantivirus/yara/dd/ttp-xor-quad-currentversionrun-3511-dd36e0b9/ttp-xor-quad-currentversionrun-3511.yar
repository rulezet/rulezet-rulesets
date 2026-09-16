rule TTP_XOR_QUAD_CurrentVersionRun_3511 {
  strings:
    $key_3511 = { 66 7e [2] 42 70 [2] 69 5c [2] 47 7e [2] 53 65 [2] 5c 7f [2] 42 62 [2] 40 63 [2] 5b 65 [2] 47 62 [2] 5b 4d }

  condition:
    any of them
}