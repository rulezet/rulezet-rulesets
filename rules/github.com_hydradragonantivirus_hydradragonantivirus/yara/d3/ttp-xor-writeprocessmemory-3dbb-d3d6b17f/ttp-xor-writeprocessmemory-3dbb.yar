rule TTP_XOR_WriteProcessMemory_3dbb {
  strings:
    $key_3dbb = { 6a c9 [2] 58 eb [2] 5e de [2] 70 de [2] 4f c2 }

  condition:
    any of them
}