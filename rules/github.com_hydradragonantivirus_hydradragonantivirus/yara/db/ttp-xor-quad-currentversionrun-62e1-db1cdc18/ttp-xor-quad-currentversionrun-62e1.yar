rule TTP_XOR_QUAD_CurrentVersionRun_62e1 {
  strings:
    $key_62e1 = { 31 8e [2] 15 80 [2] 3e ac [2] 10 8e [2] 04 95 [2] 0b 8f [2] 15 92 [2] 17 93 [2] 0c 95 [2] 10 92 [2] 0c bd }

  condition:
    any of them
}