rule TTP_XOR_WriteProcessMemory_19da {
  strings:
    $key_19da = { 4e a8 [2] 7c 8a [2] 7a bf [2] 54 bf [2] 6b a3 }

  condition:
    any of them
}