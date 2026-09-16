rule TTP_XOR_WriteProcessMemory_7faf {
  strings:
    $key_7faf = { 28 dd [2] 1a ff [2] 1c ca [2] 32 ca [2] 0d d6 }

  condition:
    any of them
}