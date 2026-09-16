rule TTP_XOR_WriteProcessMemory_666d {
  strings:
    $key_666d = { 31 1f [2] 03 3d [2] 05 08 [2] 2b 08 [2] 14 14 }

  condition:
    any of them
}