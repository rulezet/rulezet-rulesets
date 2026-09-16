rule TTP_XOR_WriteProcessMemory_3896 {
  strings:
    $key_3896 = { 6f e4 [2] 5d c6 [2] 5b f3 [2] 75 f3 [2] 4a ef }

  condition:
    any of them
}