rule TTP_XOR_WriteProcessMemory_3faf {
  strings:
    $key_3faf = { 68 dd [2] 5a ff [2] 5c ca [2] 72 ca [2] 4d d6 }

  condition:
    any of them
}