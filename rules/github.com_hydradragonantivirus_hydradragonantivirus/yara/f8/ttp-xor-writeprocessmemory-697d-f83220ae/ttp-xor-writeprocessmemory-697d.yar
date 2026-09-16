rule TTP_XOR_WriteProcessMemory_697d {
  strings:
    $key_697d = { 3e 0f [2] 0c 2d [2] 0a 18 [2] 24 18 [2] 1b 04 }

  condition:
    any of them
}