rule TTP_XOR_WriteProcessMemory_2914 {
  strings:
    $key_2914 = { 7e 66 [2] 4c 44 [2] 4a 71 [2] 64 71 [2] 5b 6d }

  condition:
    any of them
}