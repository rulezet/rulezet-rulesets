rule TTP_XOR_WriteProcessMemory_709a {
  strings:
    $key_709a = { 27 e8 [2] 15 ca [2] 13 ff [2] 3d ff [2] 02 e3 }

  condition:
    any of them
}