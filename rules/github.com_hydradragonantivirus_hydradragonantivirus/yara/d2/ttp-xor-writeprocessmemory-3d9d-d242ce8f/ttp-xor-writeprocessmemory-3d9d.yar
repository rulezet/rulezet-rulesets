rule TTP_XOR_WriteProcessMemory_3d9d {
  strings:
    $key_3d9d = { 6a ef [2] 58 cd [2] 5e f8 [2] 70 f8 [2] 4f e4 }

  condition:
    any of them
}