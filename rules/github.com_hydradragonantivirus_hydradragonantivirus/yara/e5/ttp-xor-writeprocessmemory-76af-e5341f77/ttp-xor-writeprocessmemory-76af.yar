rule TTP_XOR_WriteProcessMemory_76af {
  strings:
    $key_76af = { 21 dd [2] 13 ff [2] 15 ca [2] 3b ca [2] 04 d6 }

  condition:
    any of them
}