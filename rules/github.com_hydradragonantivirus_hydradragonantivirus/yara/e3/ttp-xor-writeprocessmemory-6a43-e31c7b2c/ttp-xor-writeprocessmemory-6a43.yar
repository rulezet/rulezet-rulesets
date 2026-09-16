rule TTP_XOR_WriteProcessMemory_6a43 {
  strings:
    $key_6a43 = { 3d 31 [2] 0f 13 [2] 09 26 [2] 27 26 [2] 18 3a }

  condition:
    any of them
}