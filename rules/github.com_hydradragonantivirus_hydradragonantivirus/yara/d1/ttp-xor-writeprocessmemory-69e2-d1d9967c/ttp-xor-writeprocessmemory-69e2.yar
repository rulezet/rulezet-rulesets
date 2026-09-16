rule TTP_XOR_WriteProcessMemory_69e2 {
  strings:
    $key_69e2 = { 3e 90 [2] 0c b2 [2] 0a 87 [2] 24 87 [2] 1b 9b }

  condition:
    any of them
}