rule TTP_XOR_WriteProcessMemory_5a43 {
  strings:
    $key_5a43 = { 0d 31 [2] 3f 13 [2] 39 26 [2] 17 26 [2] 28 3a }

  condition:
    any of them
}