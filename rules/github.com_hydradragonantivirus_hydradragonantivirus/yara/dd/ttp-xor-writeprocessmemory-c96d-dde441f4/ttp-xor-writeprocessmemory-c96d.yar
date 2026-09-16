rule TTP_XOR_WriteProcessMemory_c96d {
  strings:
    $key_c96d = { 9e 1f [2] ac 3d [2] aa 08 [2] 84 08 [2] bb 14 }

  condition:
    any of them
}