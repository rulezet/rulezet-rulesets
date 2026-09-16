rule TTP_XOR_WriteProcessMemory_7d54 {
  strings:
    $key_7d54 = { 2a 26 [2] 18 04 [2] 1e 31 [2] 30 31 [2] 0f 2d }

  condition:
    any of them
}