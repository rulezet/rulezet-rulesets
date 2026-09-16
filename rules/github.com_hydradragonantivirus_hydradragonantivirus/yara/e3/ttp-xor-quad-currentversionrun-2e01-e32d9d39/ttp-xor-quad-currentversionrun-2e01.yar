rule TTP_XOR_QUAD_CurrentVersionRun_2e01 {
  strings:
    $key_2e01 = { 7d 6e [2] 59 60 [2] 72 4c [2] 5c 6e [2] 48 75 [2] 47 6f [2] 59 72 [2] 5b 73 [2] 40 75 [2] 5c 72 [2] 40 5d }

  condition:
    any of them
}