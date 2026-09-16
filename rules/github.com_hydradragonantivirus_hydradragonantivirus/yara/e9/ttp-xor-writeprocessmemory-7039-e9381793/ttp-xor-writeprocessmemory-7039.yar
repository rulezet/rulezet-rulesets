rule TTP_XOR_WriteProcessMemory_7039 {
  strings:
    $key_7039 = { 27 4b [2] 15 69 [2] 13 5c [2] 3d 5c [2] 02 40 }

  condition:
    any of them
}