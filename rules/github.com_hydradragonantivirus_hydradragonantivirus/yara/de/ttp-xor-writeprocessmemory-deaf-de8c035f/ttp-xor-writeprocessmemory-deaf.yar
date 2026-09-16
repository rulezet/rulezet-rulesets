rule TTP_XOR_WriteProcessMemory_deaf {
  strings:
    $key_deaf = { 89 dd [2] bb ff [2] bd ca [2] 93 ca [2] ac d6 }

  condition:
    any of them
}