rule TTP_XOR_WriteProcessMemory_7dce {
  strings:
    $key_7dce = { 2a bc [2] 18 9e [2] 1e ab [2] 30 ab [2] 0f b7 }

  condition:
    any of them
}