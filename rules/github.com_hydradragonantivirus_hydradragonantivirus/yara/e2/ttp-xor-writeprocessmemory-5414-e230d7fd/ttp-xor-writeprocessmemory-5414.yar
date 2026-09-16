rule TTP_XOR_WriteProcessMemory_5414 {
  strings:
    $key_5414 = { 03 66 [2] 31 44 [2] 37 71 [2] 19 71 [2] 26 6d }

  condition:
    any of them
}