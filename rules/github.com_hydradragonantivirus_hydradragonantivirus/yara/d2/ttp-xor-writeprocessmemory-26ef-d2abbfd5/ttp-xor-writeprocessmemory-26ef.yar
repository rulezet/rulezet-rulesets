rule TTP_XOR_WriteProcessMemory_26ef {
  strings:
    $key_26ef = { 71 9d [2] 43 bf [2] 45 8a [2] 6b 8a [2] 54 96 }

  condition:
    any of them
}