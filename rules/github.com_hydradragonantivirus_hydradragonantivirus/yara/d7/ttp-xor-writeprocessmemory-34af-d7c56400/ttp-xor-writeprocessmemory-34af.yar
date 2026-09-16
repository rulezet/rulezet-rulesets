rule TTP_XOR_WriteProcessMemory_34af {
  strings:
    $key_34af = { 63 dd [2] 51 ff [2] 57 ca [2] 79 ca [2] 46 d6 }

  condition:
    any of them
}