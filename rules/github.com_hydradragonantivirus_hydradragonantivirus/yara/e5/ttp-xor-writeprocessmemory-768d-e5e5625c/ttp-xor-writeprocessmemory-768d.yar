rule TTP_XOR_WriteProcessMemory_768d {
  strings:
    $key_768d = { 21 ff [2] 13 dd [2] 15 e8 [2] 3b e8 [2] 04 f4 }

  condition:
    any of them
}