rule TTP_XOR_WriteProcessMemory_6afb {
  strings:
    $key_6afb = { 3d 89 [2] 0f ab [2] 09 9e [2] 27 9e [2] 18 82 }

  condition:
    any of them
}