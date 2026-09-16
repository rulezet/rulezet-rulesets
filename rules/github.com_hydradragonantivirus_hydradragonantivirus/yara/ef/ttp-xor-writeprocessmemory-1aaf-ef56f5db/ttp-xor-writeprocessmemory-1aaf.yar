rule TTP_XOR_WriteProcessMemory_1aaf {
  strings:
    $key_1aaf = { 4d dd [2] 7f ff [2] 79 ca [2] 57 ca [2] 68 d6 }

  condition:
    any of them
}