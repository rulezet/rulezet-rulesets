rule TTP_XOR_WriteProcessMemory_0424 {
  strings:
    $key_0424 = { 53 56 [2] 61 74 [2] 67 41 [2] 49 41 [2] 76 5d }

  condition:
    any of them
}