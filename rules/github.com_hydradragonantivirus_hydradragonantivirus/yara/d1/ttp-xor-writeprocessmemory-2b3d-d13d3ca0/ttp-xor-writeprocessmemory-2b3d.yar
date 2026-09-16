rule TTP_XOR_WriteProcessMemory_2b3d {
  strings:
    $key_2b3d = { 7c 4f [2] 4e 6d [2] 48 58 [2] 66 58 [2] 59 44 }

  condition:
    any of them
}