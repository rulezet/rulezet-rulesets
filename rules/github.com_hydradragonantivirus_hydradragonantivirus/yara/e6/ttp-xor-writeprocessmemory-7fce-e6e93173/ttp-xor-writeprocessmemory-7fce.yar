rule TTP_XOR_WriteProcessMemory_7fce {
  strings:
    $key_7fce = { 28 bc [2] 1a 9e [2] 1c ab [2] 32 ab [2] 0d b7 }

  condition:
    any of them
}