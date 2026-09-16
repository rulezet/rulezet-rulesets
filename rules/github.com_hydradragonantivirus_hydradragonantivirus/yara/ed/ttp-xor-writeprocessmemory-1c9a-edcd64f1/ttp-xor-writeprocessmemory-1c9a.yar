rule TTP_XOR_WriteProcessMemory_1c9a {
  strings:
    $key_1c9a = { 4b e8 [2] 79 ca [2] 7f ff [2] 51 ff [2] 6e e3 }

  condition:
    any of them
}