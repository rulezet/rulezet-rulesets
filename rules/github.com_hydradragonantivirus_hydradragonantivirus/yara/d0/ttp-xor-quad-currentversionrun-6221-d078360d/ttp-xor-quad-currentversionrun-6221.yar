rule TTP_XOR_QUAD_CurrentVersionRun_6221 {
  strings:
    $key_6221 = { 31 4e [2] 15 40 [2] 3e 6c [2] 10 4e [2] 04 55 [2] 0b 4f [2] 15 52 [2] 17 53 [2] 0c 55 [2] 10 52 [2] 0c 7d }

  condition:
    any of them
}