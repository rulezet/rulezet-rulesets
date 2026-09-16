rule TTP_XOR_WriteProcessMemory_548d {
  strings:
    $key_548d = { 03 ff [2] 31 dd [2] 37 e8 [2] 19 e8 [2] 26 f4 }

  condition:
    any of them
}