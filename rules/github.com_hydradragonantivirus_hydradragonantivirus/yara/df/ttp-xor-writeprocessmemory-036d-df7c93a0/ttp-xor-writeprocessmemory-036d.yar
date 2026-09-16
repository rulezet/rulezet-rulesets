rule TTP_XOR_WriteProcessMemory_036d {
  strings:
    $key_036d = { 54 1f [2] 66 3d [2] 60 08 [2] 4e 08 [2] 71 14 }

  condition:
    any of them
}