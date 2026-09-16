rule TTP_XOR_WriteProcessMemory_266d {
  strings:
    $key_266d = { 71 1f [2] 43 3d [2] 45 08 [2] 6b 08 [2] 54 14 }

  condition:
    any of them
}