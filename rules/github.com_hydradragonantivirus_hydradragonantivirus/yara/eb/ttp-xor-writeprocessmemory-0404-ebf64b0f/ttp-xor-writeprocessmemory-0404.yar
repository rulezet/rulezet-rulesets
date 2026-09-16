rule TTP_XOR_WriteProcessMemory_0404 {
  strings:
    $key_0404 = { 53 76 [2] 61 54 [2] 67 61 [2] 49 61 [2] 76 7d }

  condition:
    any of them
}