rule TTP_XOR_WriteProcessMemory_5b03 {
  strings:
    $key_5b03 = { 0c 71 [2] 3e 53 [2] 38 66 [2] 16 66 [2] 29 7a }

  condition:
    any of them
}