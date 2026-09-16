rule TTP_XOR_WriteProcessMemory_0914 {
  strings:
    $key_0914 = { 5e 66 [2] 6c 44 [2] 6a 71 [2] 44 71 [2] 7b 6d }

  condition:
    any of them
}