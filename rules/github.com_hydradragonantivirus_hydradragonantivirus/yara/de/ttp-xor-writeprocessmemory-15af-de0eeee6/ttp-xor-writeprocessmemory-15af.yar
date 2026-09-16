rule TTP_XOR_WriteProcessMemory_15af {
  strings:
    $key_15af = { 42 dd [2] 70 ff [2] 76 ca [2] 58 ca [2] 67 d6 }

  condition:
    any of them
}