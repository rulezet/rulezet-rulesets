rule TTP_XOR_WriteProcessMemory_fb3d {
  strings:
    $key_fb3d = { ac 4f [2] 9e 6d [2] 98 58 [2] b6 58 [2] 89 44 }

  condition:
    any of them
}