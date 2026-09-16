rule TTP_XOR_WriteProcessMemory_533b {
  strings:
    $key_533b = { 04 49 [2] 36 6b [2] 30 5e [2] 1e 5e [2] 21 42 }

  condition:
    any of them
}