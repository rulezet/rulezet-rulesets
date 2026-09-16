rule TTP_XOR_WriteProcessMemory_291d {
  strings:
    $key_291d = { 7e 6f [2] 4c 4d [2] 4a 78 [2] 64 78 [2] 5b 64 }

  condition:
    any of them
}