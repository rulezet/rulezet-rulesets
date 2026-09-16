rule TTP_XOR_WriteProcessMemory_26da {
  strings:
    $key_26da = { 71 a8 [2] 43 8a [2] 45 bf [2] 6b bf [2] 54 a3 }

  condition:
    any of them
}