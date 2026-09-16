rule TTP_XOR_WriteProcessMemory_e2af {
  strings:
    $key_e2af = { b5 dd [2] 87 ff [2] 81 ca [2] af ca [2] 90 d6 }

  condition:
    any of them
}