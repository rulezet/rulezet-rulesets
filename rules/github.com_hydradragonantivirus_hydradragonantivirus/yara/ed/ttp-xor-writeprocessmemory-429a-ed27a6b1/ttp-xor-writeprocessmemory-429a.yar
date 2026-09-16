rule TTP_XOR_WriteProcessMemory_429a {
  strings:
    $key_429a = { 15 e8 [2] 27 ca [2] 21 ff [2] 0f ff [2] 30 e3 }

  condition:
    any of them
}