rule TTP_XOR_WriteProcessMemory_dfaf {
  strings:
    $key_dfaf = { 88 dd [2] ba ff [2] bc ca [2] 92 ca [2] ad d6 }

  condition:
    any of them
}