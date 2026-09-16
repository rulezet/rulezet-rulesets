rule TTP_XOR_WriteProcessMemory_7009 {
  strings:
    $key_7009 = { 27 7b [2] 15 59 [2] 13 6c [2] 3d 6c [2] 02 70 }

  condition:
    any of them
}