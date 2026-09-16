rule TTP_XOR_WriteProcessMemory_78ef {
  strings:
    $key_78ef = { 2f 9d [2] 1d bf [2] 1b 8a [2] 35 8a [2] 0a 96 }

  condition:
    any of them
}