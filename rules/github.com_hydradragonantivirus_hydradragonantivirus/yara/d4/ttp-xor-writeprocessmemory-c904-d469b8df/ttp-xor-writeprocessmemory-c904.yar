rule TTP_XOR_WriteProcessMemory_c904 {
  strings:
    $key_c904 = { 9e 76 [2] ac 54 [2] aa 61 [2] 84 61 [2] bb 7d }

  condition:
    any of them
}