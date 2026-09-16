rule TTP_XOR_WriteProcessMemory_4aaf {
  strings:
    $key_4aaf = { 1d dd [2] 2f ff [2] 29 ca [2] 07 ca [2] 38 d6 }

  condition:
    any of them
}