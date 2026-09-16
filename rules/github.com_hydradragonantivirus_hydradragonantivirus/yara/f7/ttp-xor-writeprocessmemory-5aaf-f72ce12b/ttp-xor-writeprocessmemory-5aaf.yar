rule TTP_XOR_WriteProcessMemory_5aaf {
  strings:
    $key_5aaf = { 0d dd [2] 3f ff [2] 39 ca [2] 17 ca [2] 28 d6 }

  condition:
    any of them
}