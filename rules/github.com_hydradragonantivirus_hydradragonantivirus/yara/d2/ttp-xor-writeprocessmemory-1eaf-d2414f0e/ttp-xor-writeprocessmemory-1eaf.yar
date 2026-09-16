rule TTP_XOR_WriteProcessMemory_1eaf {
  strings:
    $key_1eaf = { 49 dd [2] 7b ff [2] 7d ca [2] 53 ca [2] 6c d6 }

  condition:
    any of them
}