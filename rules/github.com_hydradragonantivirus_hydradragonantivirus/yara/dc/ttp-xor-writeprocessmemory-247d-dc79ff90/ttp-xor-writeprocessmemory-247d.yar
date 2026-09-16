rule TTP_XOR_WriteProcessMemory_247d {
  strings:
    $key_247d = { 73 0f [2] 41 2d [2] 47 18 [2] 69 18 [2] 56 04 }

  condition:
    any of them
}