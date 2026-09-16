rule TTP_XOR_WriteProcessMemory_e952 {
  strings:
    $key_e952 = { be 20 [2] 8c 02 [2] 8a 37 [2] a4 37 [2] 9b 2b }

  condition:
    any of them
}