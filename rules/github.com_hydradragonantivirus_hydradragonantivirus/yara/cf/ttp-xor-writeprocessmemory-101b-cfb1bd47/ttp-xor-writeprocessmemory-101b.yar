rule TTP_XOR_WriteProcessMemory_101b {
  strings:
    $key_101b = { 47 69 [2] 75 4b [2] 73 7e [2] 5d 7e [2] 62 62 }

  condition:
    any of them
}