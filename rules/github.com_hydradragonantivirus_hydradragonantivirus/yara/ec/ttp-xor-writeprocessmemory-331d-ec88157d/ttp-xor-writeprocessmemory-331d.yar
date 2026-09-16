rule TTP_XOR_WriteProcessMemory_331d {
  strings:
    $key_331d = { 64 6f [2] 56 4d [2] 50 78 [2] 7e 78 [2] 41 64 }

  condition:
    any of them
}