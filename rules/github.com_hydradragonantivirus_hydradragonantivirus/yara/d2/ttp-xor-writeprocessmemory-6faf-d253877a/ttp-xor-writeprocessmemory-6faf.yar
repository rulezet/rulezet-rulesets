rule TTP_XOR_WriteProcessMemory_6faf {
  strings:
    $key_6faf = { 38 dd [2] 0a ff [2] 0c ca [2] 22 ca [2] 1d d6 }

  condition:
    any of them
}