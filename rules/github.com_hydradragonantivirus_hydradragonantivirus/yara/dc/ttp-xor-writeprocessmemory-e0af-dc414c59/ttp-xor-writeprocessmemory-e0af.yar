rule TTP_XOR_WriteProcessMemory_e0af {
  strings:
    $key_e0af = { b7 dd [2] 85 ff [2] 83 ca [2] ad ca [2] 92 d6 }

  condition:
    any of them
}