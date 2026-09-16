rule TTP_XOR_WriteProcessMemory_0433 {
  strings:
    $key_0433 = { 53 41 [2] 61 63 [2] 67 56 [2] 49 56 [2] 76 4a }

  condition:
    any of them
}