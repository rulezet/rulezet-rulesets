rule TTP_XOR_WriteProcessMemory_71af {
  strings:
    $key_71af = { 26 dd [2] 14 ff [2] 12 ca [2] 3c ca [2] 03 d6 }

  condition:
    any of them
}