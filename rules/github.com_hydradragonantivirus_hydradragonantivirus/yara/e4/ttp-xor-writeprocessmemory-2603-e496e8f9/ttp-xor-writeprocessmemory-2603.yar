rule TTP_XOR_WriteProcessMemory_2603 {
  strings:
    $key_2603 = { 71 71 [2] 43 53 [2] 45 66 [2] 6b 66 [2] 54 7a }

  condition:
    any of them
}