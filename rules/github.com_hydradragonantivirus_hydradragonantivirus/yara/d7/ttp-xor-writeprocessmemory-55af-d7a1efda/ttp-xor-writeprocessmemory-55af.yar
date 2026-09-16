rule TTP_XOR_WriteProcessMemory_55af {
  strings:
    $key_55af = { 02 dd [2] 30 ff [2] 36 ca [2] 18 ca [2] 27 d6 }

  condition:
    any of them
}