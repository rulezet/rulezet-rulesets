rule TTP_XOR_WriteProcessMemory_eeaf {
  strings:
    $key_eeaf = { b9 dd [2] 8b ff [2] 8d ca [2] a3 ca [2] 9c d6 }

  condition:
    any of them
}