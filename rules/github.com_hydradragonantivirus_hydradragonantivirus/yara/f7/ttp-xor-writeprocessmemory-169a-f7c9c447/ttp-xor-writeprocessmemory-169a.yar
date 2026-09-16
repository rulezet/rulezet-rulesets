rule TTP_XOR_WriteProcessMemory_169a {
  strings:
    $key_169a = { 41 e8 [2] 73 ca [2] 75 ff [2] 5b ff [2] 64 e3 }

  condition:
    any of them
}