rule TTP_XOR_WriteProcessMemory_2ca5 {
  strings:
    $key_2ca5 = { 7b d7 [2] 49 f5 [2] 4f c0 [2] 61 c0 [2] 5e dc }

  condition:
    any of them
}