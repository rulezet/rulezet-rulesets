rule TTP_XOR_WriteProcessMemory_0aaf {
  strings:
    $key_0aaf = { 5d dd [2] 6f ff [2] 69 ca [2] 47 ca [2] 78 d6 }

  condition:
    any of them
}