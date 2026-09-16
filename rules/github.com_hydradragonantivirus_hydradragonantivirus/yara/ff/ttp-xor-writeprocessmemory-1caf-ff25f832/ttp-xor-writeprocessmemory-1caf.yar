rule TTP_XOR_WriteProcessMemory_1caf {
  strings:
    $key_1caf = { 4b dd [2] 79 ff [2] 7f ca [2] 51 ca [2] 6e d6 }

  condition:
    any of them
}