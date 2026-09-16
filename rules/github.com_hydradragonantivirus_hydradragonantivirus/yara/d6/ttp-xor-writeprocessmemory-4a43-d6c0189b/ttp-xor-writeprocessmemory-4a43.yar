rule TTP_XOR_WriteProcessMemory_4a43 {
  strings:
    $key_4a43 = { 1d 31 [2] 2f 13 [2] 29 26 [2] 07 26 [2] 38 3a }

  condition:
    any of them
}