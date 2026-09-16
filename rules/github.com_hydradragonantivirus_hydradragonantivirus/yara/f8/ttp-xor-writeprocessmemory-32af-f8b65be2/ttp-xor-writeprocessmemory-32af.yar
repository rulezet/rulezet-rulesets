rule TTP_XOR_WriteProcessMemory_32af {
  strings:
    $key_32af = { 65 dd [2] 57 ff [2] 51 ca [2] 7f ca [2] 40 d6 }

  condition:
    any of them
}