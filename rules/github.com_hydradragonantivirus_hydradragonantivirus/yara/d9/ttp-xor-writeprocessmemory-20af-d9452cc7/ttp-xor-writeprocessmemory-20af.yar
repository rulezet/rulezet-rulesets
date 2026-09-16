rule TTP_XOR_WriteProcessMemory_20af {
  strings:
    $key_20af = { 77 dd [2] 45 ff [2] 43 ca [2] 6d ca [2] 52 d6 }

  condition:
    any of them
}