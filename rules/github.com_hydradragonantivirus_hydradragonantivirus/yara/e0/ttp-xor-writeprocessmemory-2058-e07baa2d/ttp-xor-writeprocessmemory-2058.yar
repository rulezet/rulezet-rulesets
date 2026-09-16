rule TTP_XOR_WriteProcessMemory_2058 {
  strings:
    $key_2058 = { 77 2a [2] 45 08 [2] 43 3d [2] 6d 3d [2] 52 21 }

  condition:
    any of them
}