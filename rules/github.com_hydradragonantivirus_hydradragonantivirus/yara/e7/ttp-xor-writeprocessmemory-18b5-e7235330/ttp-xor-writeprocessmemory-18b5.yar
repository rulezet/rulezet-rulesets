rule TTP_XOR_WriteProcessMemory_18b5 {
  strings:
    $key_18b5 = { 4f c7 [2] 7d e5 [2] 7b d0 [2] 55 d0 [2] 6a cc }

  condition:
    any of them
}