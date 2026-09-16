rule TTP_XOR_WriteProcessMemory_789d {
  strings:
    $key_789d = { 2f ef [2] 1d cd [2] 1b f8 [2] 35 f8 [2] 0a e4 }

  condition:
    any of them
}